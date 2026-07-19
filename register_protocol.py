#!/usr/bin/env python3
"""Grok / xAI protocol registration (HTTP signup RPCs + Turnstile only).

Interactive start (like reference project):
  - Turnstile browser: local Chrome | Roxy fingerprint
  - Proxy: on / off, pool source (Roxy manager / proxies.txt / single)
  - Register count

Proxy logic aligned with grok-register:
  proxies > Roxy IP manager (roxy mode) > proxies_file > proxy
  blacklist after N failures; random/sticky pick
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import sys
import threading
import time
from pathlib import Path

# Ensure this project root wins over sibling / reference dirs on sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
else:
    # move to front if already present later
    try:
        sys.path.remove(str(ROOT))
    except ValueError:
        pass
    sys.path.insert(0, str(ROOT))

from auth_client import (
    AuthClient,
    AuthError,
    TURNSTILE_SITEKEY,
    extract_session_cookie,
)
from cf_mail import create_address, wait_code
from cpa_export import export_cpa_from_sso
import proxyutil as px

DEFAULT_CONFIG = ROOT / "config.json"
_LEDGER_LOCK = threading.Lock()
_STOP = threading.Event()


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_config(path: Path, cfg: dict) -> None:
    path.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def gen_password(n: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*" for c in pw)
        ):
            return pw


def solve_turnstile(
    cfg: dict, log, proxy: str | None = None, *, worker_id: int = 0
) -> str:
    token = str(cfg.get("turnstile_token") or "").strip()
    if token:
        log("[turnstile] using config.turnstile_token")
        return token

    # 1) CapSolver (optional, pure HTTP)
    api_key = str(cfg.get("capsolver_api_key") or "").strip()
    if api_key:
        try:
            import requests
        except ImportError:
            log("[turnstile] requests missing for capsolver")
            requests = None  # type: ignore
        if requests is not None:
            sitekey = str(cfg.get("turnstile_sitekey") or TURNSTILE_SITEKEY)
            create_payload = {
                "clientKey": api_key,
                "task": {
                    "type": "AntiTurnstileTaskProxyLess",
                    "websiteURL": "https://accounts.x.ai/sign-up?redirect=grok-com",
                    "websiteKey": sitekey,
                },
            }
            log("[turnstile] creating CapSolver task…")
            r = requests.post(
                "https://api.capsolver.com/createTask",
                json=create_payload,
                timeout=60,
            )
            data = r.json()
            if data.get("errorId"):
                log(f"[turnstile] createTask error: {data}")
            else:
                task_id = data.get("taskId")
                for _ in range(60):
                    time.sleep(2)
                    rr = requests.post(
                        "https://api.capsolver.com/getTaskResult",
                        json={"clientKey": api_key, "taskId": task_id},
                        timeout=60,
                    )
                    res = rr.json()
                    if res.get("status") == "ready":
                        tok = (res.get("solution") or {}).get("token") or ""
                        log(f"[turnstile] capsolver ok len={len(tok)}")
                        return tok
                    if res.get("errorId"):
                        log(f"[turnstile] getTaskResult error: {res}")
                        break
                else:
                    log("[turnstile] capsolver timeout")

    # 2) Minimal browser (local Chrome or Roxy) — only for Turnstile
    if cfg.get("turnstile_browser", True):
        try:
            from turnstile_browser import solve_turnstile_browser
        except ImportError as exc:
            log(f"[turnstile] browser helper missing: {exc}")
            return ""
        backend = str(cfg.get("browser_backend") or "local").strip().lower()
        return solve_turnstile_browser(
            proxy=proxy,
            timeout=float(cfg.get("turnstile_timeout_sec") or 90),
            headless=bool(cfg.get("turnstile_headless", False)),
            log=log,
            sitekey=str(cfg.get("turnstile_sitekey") or TURNSTILE_SITEKEY),
            backend=backend,
            config=cfg,
            worker_id=worker_id,
        )
    return ""


def _resolve_output(path: Path) -> Path:
    if not path.is_absolute():
        path = ROOT / path
    return path


def request_stop() -> None:
    _STOP.set()


def clear_stop() -> None:
    _STOP.clear()


def should_stop() -> bool:
    return _STOP.is_set()


def save_account_json(path: Path, record: dict) -> Path:
    """Append one account object into a JSON array ledger file (thread-safe)."""
    path = _resolve_output(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LEDGER_LOCK:
        items: list = []
        if path.exists() and path.stat().st_size > 0:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    items = raw
                elif isinstance(raw, dict):
                    items = [raw]
            except Exception:
                bak = path.with_suffix(path.suffix + ".bak")
                try:
                    path.replace(bak)
                except Exception:
                    pass
                items = []
        items.append(record)
        path.write_text(
            json.dumps(items, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return path


def register_one(
    cfg: dict,
    log=print,
    *,
    worker_id: int = 0,
    proxy_pool: list[str] | None = None,
) -> dict:
    """Register one account. Proxy pick + blacklist same as reference project.

    Dead / hanging proxies: short connect timeout + exclude already-tried IPs
    so the same SOCKS is not reused on the next attempt.
    """
    px.bind_config(cfg)
    pool = list(proxy_pool if proxy_pool is not None else px.load_proxy_pool(cfg, log=log))
    try:
        configured_retries = int(cfg.get("proxy_retry_per_account", 0) or 0)
    except (TypeError, ValueError):
        configured_retries = 0
    # default: try up to pool size (cap 10), at least 3 when proxy on
    if configured_retries > 0:
        max_proxy_retries = max(1, configured_retries)
    elif cfg.get("use_proxy", True) and pool:
        max_proxy_retries = max(3, min(10, len(pool)))
    else:
        max_proxy_retries = 1

    last_err: Exception | None = None
    tried: set[str] = set()
    local_fallback = px.normalize_proxy_url(cfg.get("proxy", ""))
    tried_local = False

    for attempt in range(max_proxy_retries):
        if should_stop():
            raise RuntimeError("cancelled by user")
        proxy = px.effective_register_proxy(
            cfg,
            worker_id=worker_id + attempt,
            pool=pool,
            log=log,
            exclude=tried,
        )
        # pool exhausted this round → try local fallback once, then give up
        if not proxy and cfg.get("use_proxy", True):
            if local_fallback and not tried_local:
                key = px.proxy_identity(local_fallback)
                if key not in tried:
                    proxy = local_fallback
                    tried_local = True
                    log(
                        f"[*] 代理池本轮已试尽，回退本地代理: "
                        f"{px.proxy_log_label(proxy)}"
                    )
            if not proxy:
                log("[!] 无更多可用代理可换")
                break

        proxy_orig = proxy or ""
        if proxy_orig:
            tried.add(px.proxy_identity(proxy_orig) or proxy_orig)

        # 711 / rotgb etc. only reachable via local Clash — spin HTTP bridge
        client_proxy = (
            px.apply_local_chain(proxy_orig, cfg, log=log) if proxy_orig else ""
        )
        px.set_worker_proxy(client_proxy or None)
        excluded_n = max(0, len(tried) - (1 if proxy_orig else 0))
        log(
            f"[*] 使用代理 attempt={attempt + 1}/{max_proxy_retries} "
            f"{px.proxy_log_label(client_proxy or proxy_orig) if (client_proxy or proxy_orig) else '(direct)'}"
            + (f" 已排除={excluded_n}" if excluded_n else "")
        )
        try:
            return _register_one_with_proxy(
                cfg,
                log,
                proxy=client_proxy or None,
                worker_id=worker_id,
                proxy_orig=proxy_orig or None,
            )
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            retryable = px.is_retryable_proxy_error(exc)
            if proxy_orig and retryable:
                px.report_proxy_failure(proxy_orig, str(exc), log=log, cfg=cfg)
            if retryable and attempt + 1 < max_proxy_retries:
                log(
                    f"[!] 代理异常，换代理重试 "
                    f"({attempt + 1}/{max_proxy_retries}): {exc}"
                )
                continue
            if retryable:
                log(f"[!] 代理重试耗尽: {exc}")
            raise
        finally:
            px.set_worker_proxy(None)

    if last_err is not None:
        raise last_err
    raise RuntimeError("no proxy available to attempt registration")


def _register_one_with_proxy(
    cfg: dict,
    log,
    *,
    proxy: str | None,
    worker_id: int = 0,
    proxy_orig: str | None = None,
) -> dict:
    api_base = str(cfg.get("cloudflare_api_base") or "").rstrip("/")
    api_key = str(cfg.get("cloudflare_api_key") or "")
    domains = cfg.get("default_domains") or ["oo-ooo.fun"]
    domain = domains[int(time.time()) % len(domains)]
    # proxy = client-facing (may be chain bridge); proxy_orig = pool identity
    proxy_orig = (proxy_orig or proxy or "").strip() or None

    log(f"[1/6] create temp email domain={domain}")
    if proxy:
        log(f"      proxy={px.proxy_log_label(proxy)}")
    else:
        log("      proxy=direct")
    email, jwt = create_address(api_base, api_key, domain=domain)
    password = gen_password()
    log(f"      email={email}")

    connect_to = float(cfg.get("proxy_connect_timeout", 12) or 12)
    read_to = float(cfg.get("proxy_read_timeout", 25) or 25)
    client = AuthClient(
        proxy=proxy,
        log=log,
        connect_timeout=connect_to,
        read_timeout=read_to,
    )
    client.warm()

    if should_stop():
        raise RuntimeError("cancelled by user")

    log("[2/6] CreateEmailValidationCode")
    client.create_email_validation_code(email)

    log("[3/6] wait verification code")
    code = wait_code(api_base, jwt, api_key, timeout=120, poll_interval=3, log=log)
    log(f"      code={code}")

    if should_stop():
        raise RuntimeError("cancelled by user")

    log("[4/6] VerifyEmailValidationCode")
    client.verify_email_validation_code(email, code)

    log("[5/6] solve Turnstile")
    turnstile = solve_turnstile(cfg, log, proxy=proxy, worker_id=worker_id)
    if not turnstile:
        raise AuthError(
            "no turnstile token — set capsolver_api_key / turnstile_token "
            "or fix browser solver (local/roxy)"
        )

    given = str(cfg.get("given_name") or "John")
    family = str(cfg.get("family_name") or "Doe")
    tos = int(cfg.get("tos_accepted_version") or 1)

    log("[6/6] CreateUserAndSession")
    result = None
    err: Exception | None = None
    try:
        result = client.create_user_and_session(
            email=email,
            password=password,
            email_validation_code=code,
            given_name=given,
            family_name=family,
            tos_accepted_version=tos,
            turnstile_token=turnstile,
            use_v2=True,
        )
    except AuthError as exc:
        err = exc
        log(f"[!] direct RPC create failed: {exc}")
        log("[*] retry via Next.js server action")
        sa = client.create_user_via_server_action(
            email=email,
            password=password,
            email_validation_code=code,
            turnstile_token=turnstile,
            given_name=given,
            family_name=family,
            tos_accepted_version=tos,
        )
        result = sa

    frames = (result or {}).get("frames") or []
    sso = ""
    try:
        sso = client.get_sso() or extract_session_cookie(frames)
    except Exception as exc:  # noqa: BLE001
        log(f"[!] extract sso skipped: {exc}")
    if sso:
        try:
            client.session.cookies.set("sso", sso, domain=".x.ai")
            client.session.cookies.set("sso-rw", sso, domain=".x.ai")
        except Exception:
            pass
        if cfg.get("set_tos_on_create", False):
            try:
                client.set_tos_accepted_version(tos)
            except Exception as exc:  # noqa: BLE001
                log(f"[!] SetTosAcceptedVersion: {exc}")

    create_ok = False
    status = str((result or {}).get("status") if result else "")
    if err is None and result is not None:
        if "http_status" in (result or {}) and "frames" not in (result or {}):
            create_ok = int(result.get("http_status") or 500) < 400
        else:
            create_ok = status in ("", "0", "None") or status == "0"

    out = {
        "ok": bool(create_ok),
        "email": email,
        "password": password,
        "created_at": int(time.time()),
        "domain": domain,
        "code": code,
        "turnstile_used": bool(turnstile),
        "proxy": px.proxy_log_label(proxy_orig or proxy) if (proxy_orig or proxy) else "",
        "result_status": (result or {}).get("status"),
        "result_message": (result or {}).get("message") or None,
        "error": str(err) if err else None,
        "cpa_path": None,
        "cpa_ok": False,
        "cpa_push_ok": False,
    }
    if sso:
        out["sso"] = sso

    if create_ok:
        if proxy_orig or proxy:
            px.report_proxy_success(proxy_orig or proxy, cfg=cfg)
        ledger = {
            "email": email,
            "password": password,
            "created_at": out["created_at"],
            **({"sso": sso} if sso and cfg.get("save_sso", True) else {}),
        }
        out_path = save_account_json(
            Path(str(cfg.get("output_file") or "accounts.json")),
            ledger,
        )
        log(f"[+] ledger {email} → {out_path}" + (" sso=yes" if sso else " sso=missing"))

        if sso and cfg.get("cpa_export_enabled", True):
            # mint rotates pool; pass original residential (chain applied in cpa_export)
            cfg_mint = dict(cfg)
            cfg_mint["_worker_proxy"] = proxy_orig or proxy or ""
            cpa = export_cpa_from_sso(
                email=email,
                sso=sso,
                password=password,
                config=cfg_mint,
                log=log,
            )
            out["cpa_ok"] = bool(cpa.get("ok"))
            out["cpa_path"] = cpa.get("path")
            out["cpa_error"] = cpa.get("error")
            out["cpa_push_ok"] = bool(cpa.get("cpa_push_ok"))
            out["cpa_push"] = cpa.get("cpa_push")
            if cpa.get("ok"):
                log(f"[+] CPA {cpa.get('filename')} → {cpa.get('path')}")
                if cpa.get("cpa_push_ok"):
                    log(f"[+] CPA push ok ({cpa.get('filename')})")
                elif (cpa.get("cpa_push") or {}).get("skipped"):
                    log(f"[*] CPA push skipped: {(cpa.get('cpa_push') or {}).get('reason')}")
                else:
                    log(
                        f"[!] CPA push failed: "
                        f"{(cpa.get('cpa_push') or {}).get('error') or 'unknown'}"
                    )
            else:
                log(f"[!] CPA mint deferred: {cpa.get('error') or 'unknown'}")
        elif not sso:
            log("[!] no sso — CPA xai-*.json needs mint later (re-run with --mint-ledger)")
        else:
            log("[cpa] export disabled")
    else:
        log(f"[*] create not ok: {json.dumps(out, ensure_ascii=False)[:500]}")
    return out


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] 已取消")
        raise SystemExit(130)


def interactive_menu(cfg: dict, config_path: Path) -> dict:
    """CLI options aligned with reference project start flow."""
    px.bind_config(cfg)
    print("=" * 56)
    print("  GrokX 协议注册  →  CPA xai-<email>.json")
    print("  注册 RPC = 纯 HTTP；浏览器仅用于 Turnstile")
    print("=" * 56)

    backend = str(cfg.get("browser_backend") or "local").strip().lower()
    if backend in ("fingerprint", "roxybrowser"):
        backend = "roxy"
    use_proxy = bool(cfg.get("use_proxy", True))
    try:
        default_count = max(1, int(cfg.get("register_count", 1) or 1))
    except (TypeError, ValueError):
        default_count = 1

    pool = px.load_proxy_pool(cfg, log=print) if use_proxy else []
    print(f"[*] 配置: {config_path}")
    print(
        "[*] Turnstile 浏览器: "
        + ("Roxy 指纹" if backend == "roxy" else "本地 Chrome")
    )
    if use_proxy:
        if pool:
            print(
                f"[*] 代理: 开 | 池内 {len(pool)} 条 | 示例 {px.proxy_log_label(pool[0])}"
            )
        else:
            print("[*] 代理: 开 | 池空（将直连）")
    else:
        print("[*] 代理: 关（直连）")
    print(f"[*] 默认注册数量: {default_count}")
    print(
        "[*] CPA 导出: "
        + (
            "开 → " + str(cfg.get("cpa_auth_dir") or "cpa_auths")
            if cfg.get("cpa_export_enabled", True)
            else "关"
        )
    )
    print()

    # 1) browser backend (for Turnstile only)
    current_label = "2=Roxy 指纹浏览器" if backend == "roxy" else "1=本地 Chrome"
    raw_backend = _ask(
        f"请选择 Turnstile 浏览器（1=本地 Chrome，2=Roxy 指纹浏览器，"
        f"直接回车={current_label}）: "
    ).lower()
    if raw_backend in ("", "default"):
        selected = backend if backend in ("local", "roxy") else "local"
    elif raw_backend in ("1", "local", "chrome", "本地"):
        selected = "local"
    elif raw_backend in ("2", "roxy", "fingerprint", "指纹"):
        selected = "roxy"
    else:
        print("[!] 浏览器选择无效，请输入 1 或 2")
        raise SystemExit(2)

    if selected == "roxy" and not str(
        cfg.get("roxy_api_token") or cfg.get("roxy_token") or ""
    ).strip():
        print("[!] 未配置 roxy_api_token，无法使用 Roxy 指纹浏览器")
        print("    请在 config.json 填写 roxy_api_token（Roxy → API → API Key）")
        raise SystemExit(2)

    cfg["browser_backend"] = selected
    cfg["turnstile_browser"] = True
    print(
        "[*] 本次 Turnstile: "
        + ("Roxy 指纹浏览器" if selected == "roxy" else "本地 Chrome")
    )

    # 2) proxy mode: Clash 单代理 / 多代理池 / 直连
    cur_mode = str(cfg.get("proxy_mode") or "").strip().lower()
    if not cfg.get("use_proxy", True):
        cur_mode = "direct"
    elif cur_mode in ("clash", "single", "flclash", "local", "1"):
        cur_mode = "clash"
    elif cur_mode in ("multi", "pool", "multiport", "proxies", "2"):
        cur_mode = "multi"
    elif cur_mode in ("direct", "off", "none", "3"):
        cur_mode = "direct"
    else:
        # auto → prefer multi if proxies.txt has >1 live line, else clash
        cur_mode = "multi" if len(pool) > 1 else ("clash" if use_proxy else "direct")

    mode_label = {
        "clash": "1=Clash单代理",
        "multi": "2=多代理池",
        "direct": "3=直连",
    }.get(cur_mode, "1=Clash单代理")
    raw_mode = _ask(
        "请选择代理模式（"
        "1=Clash单代理 / 2=多代理池(proxies.txt) / 3=直连，"
        f"直接回车={mode_label}）: "
    ).lower()
    if raw_mode in ("", "default"):
        proxy_mode = cur_mode
    elif raw_mode in ("1", "clash", "single", "flclash", "local", "c"):
        proxy_mode = "clash"
    elif raw_mode in ("2", "multi", "pool", "multiport", "proxies", "m"):
        proxy_mode = "multi"
    elif raw_mode in ("3", "direct", "off", "none", "n", "0"):
        proxy_mode = "direct"
    else:
        print("[!] 代理模式无效，请输入 1 / 2 / 3")
        raise SystemExit(2)

    cfg["proxy_mode"] = proxy_mode
    use_proxy = proxy_mode != "direct"
    cfg["use_proxy"] = use_proxy

    if proxy_mode == "direct":
        cfg["roxy_use_proxy_manager"] = False
        print("[*] 代理模式: 直连（HTTP 注册 + Turnstile 均不挂代理）")
    elif proxy_mode == "clash":
        cfg["roxy_use_proxy_manager"] = False
        cur = str(cfg.get("proxy") or "http://127.0.0.1:7890").strip()
        raw_url = _ask(
            f"Clash/本地单代理地址（直接回车=保留 "
            f"{px.proxy_log_label(cur) if cur else 'http://127.0.0.1:7890'}）: "
        )
        if raw_url:
            cfg["proxy"] = raw_url.strip()
        elif not str(cfg.get("proxy") or "").strip():
            cfg["proxy"] = "http://127.0.0.1:7890"
        px.bind_config(cfg)
        pool = px.load_proxy_pool(cfg, log=print)
        print(
            f"[*] 代理模式: Clash 单代理 → "
            f"{px.proxy_log_label(pool[0]) if pool else '(空)'}"
        )
        if not pool:
            print("[!] config.proxy 为空，注册可能失败")
    else:
        # multi pool
        cfg["roxy_use_proxy_manager"] = False
        # optional: refresh FlClash multiport → proxies.txt
        multiport_sh = Path(__file__).resolve().parent / "flclash_multiport.sh"
        if multiport_sh.is_file() and os.access(multiport_sh, os.X_OK):
            raw_mp = _ask(
                "是否刷新多代理（FlClash 测活写入 proxies.txt）"
                "（Y=刷新 / N=用现有 proxies.txt，直接回车=N）: "
            ).lower()
            if raw_mp in ("y", "yes", "1", "是", "true", "on"):
                print("[*] 正在测活多端口节点 → proxies.txt …")
                try:
                    import subprocess

                    rc = subprocess.call(
                        [str(multiport_sh), "start"],
                        cwd=str(multiport_sh.parent),
                    )
                    if rc != 0:
                        print(f"[!] multiport 退出码 {rc}，将继续用现有 proxies.txt")
                except Exception as exc:  # noqa: BLE001
                    print(f"[!] 启动 multiport 失败: {exc}")

        # optional Roxy manager only in multi + roxy browser
        if selected == "roxy":
            current_use_mgr = bool(cfg.get("roxy_use_proxy_manager", False))
            default_mgr_label = "Y=使用" if current_use_mgr else "N=不使用"
            raw_mgr = _ask(
                "是否改用 Roxy 代理管理（一般选 N，用 proxies.txt）"
                f"（Y=Roxy / N=proxies.txt，直接回车={default_mgr_label}）: "
            ).lower()
            if raw_mgr in ("", "default"):
                use_mgr = current_use_mgr
            elif raw_mgr in ("y", "yes", "1", "是", "true", "on"):
                use_mgr = True
            elif raw_mgr in ("n", "no", "0", "否", "false", "off"):
                use_mgr = False
            else:
                print("[!] 选择无效，请输入 Y 或 N")
                raise SystemExit(2)
            cfg["roxy_use_proxy_manager"] = use_mgr
            if use_mgr:
                print("[*] 多代理来源: Roxy IP 管理（池空则回退 proxies.txt / proxy）")
            else:
                print("[*] 多代理来源: proxies.txt / config.proxies")
        else:
            print("[*] 多代理来源: proxies.txt / config.proxies")

        cur = str(cfg.get("proxy") or "").strip()
        raw_url = _ask(
            f"回退单代理 proxy（池空时用，直接回车=保留 "
            f"{px.proxy_log_label(cur) if cur else '(空)'}）: "
        )
        if raw_url:
            cfg["proxy"] = raw_url.strip()

        px.bind_config(cfg)
        pool = px.load_proxy_pool(cfg, log=print)
        if pool:
            print(
                f"[*] 代理模式: 多代理池 | {len(pool)} 条 | "
                f"示例: {px.proxy_log_label(pool[0])}"
            )
        else:
            print("[!] 多代理池为空，将回退/直连（请先填 proxies.txt 或跑 multiport）")

    # 3) register count
    raw_count = _ask(f"请输入注册数量（直接回车={default_count}）: ")
    try:
        count = int(raw_count) if raw_count else default_count
        if count < 1:
            raise ValueError
    except ValueError:
        print("[!] 注册数量无效，请输入大于 0 的整数")
        raise SystemExit(2)
    cfg["register_count"] = count

    # 4) concurrency (multi browser for Turnstile / parallel accounts)
    try:
        default_threads = max(1, int(cfg.get("register_threads", 1) or 1))
    except (TypeError, ValueError):
        default_threads = 1
    raw_threads = _ask(
        f"请输入并发数量（同时开几个浏览器/任务，直接回车={default_threads}）: "
    )
    try:
        threads = int(raw_threads) if raw_threads else default_threads
        if threads < 1:
            raise ValueError
    except ValueError:
        print("[!] 并发数量无效，请输入大于 0 的整数")
        raise SystemExit(2)
    cfg["register_threads"] = max(1, min(threads, count))

    # 5) optional headless for local only
    if selected == "local":
        cur_hl = bool(cfg.get("turnstile_headless", False))
        default_hl = "Y=无头" if cur_hl else "N=有界面"
        raw_hl = _ask(
            f"本地 Chrome 是否无头（Y=无头 / N=有界面，直接回车={default_hl}）: "
        ).lower()
        if raw_hl in ("y", "yes", "1", "是", "true", "on"):
            cfg["turnstile_headless"] = True
        elif raw_hl in ("n", "no", "0", "否", "false", "off"):
            cfg["turnstile_headless"] = False

    save_config(config_path, cfg)
    print()
    pool_n = len(px.load_proxy_pool(cfg, log=lambda _m: None)) if use_proxy else 0
    print(
        f"[*] 开始注册 count={count} threads={cfg['register_threads']} | "
        f"browser={selected} | "
        f"proxy={'on pool=' + str(pool_n) if use_proxy else 'off'}"
    )
    print()
    return cfg


def _cleanup_browsers(cfg: dict, log=print) -> None:
    """Close multi-open Turnstile seats + Roxy windows at end of batch."""
    try:
        from turnstile_browser import release_all_browsers

        n = release_all_browsers(log=log)
        if n:
            pages = int(cfg.get("browser_pages_per_window") or 3)
            log(
                f"[*] Turnstile 浏览器收尾：关闭 {n} 个窗口"
                f"（每窗最多 {pages} 标签）"
            )
    except Exception as exc:  # noqa: BLE001
        log(f"[!] Turnstile 浏览器收尾失败: {exc}")

    try:
        import proxyutil as _px

        _px.stop_proxy_chains()
        log("[*] 链式代理桥已全部关闭")
    except Exception as exc:  # noqa: BLE001
        log(f"[!] 链式代理桥收尾失败: {exc}")

    if str(cfg.get("browser_backend") or "").lower() not in (
        "roxy",
        "fingerprint",
        "roxybrowser",
    ):
        return
    try:
        ref = __import__("os").environ.get("GROKX_BROWSER_BACKEND_DIR", "")
        # append only — never insert front (would shadow GrokX modules)
        if ref not in sys.path:
            sys.path.append(ref)
        import browser_backend as bb

        log("[*] Roxy 收尾：关闭本轮指纹浏览器进程…")
        n = bb.cleanup_roxy_windows(cfg, log=log)
        log(f"[*] Roxy 收尾完成（处理 {n} 个窗口/进程）")
    except Exception as exc:  # noqa: BLE001
        log(f"[!] Roxy 收尾失败: {exc}")


def run_batch(
    cfg: dict,
    count: int,
    *,
    concurrency: int | None = None,
    log=print,
    on_result=None,
) -> int:
    """Register `count` accounts with up to `concurrency` parallel workers.

    Each worker uses its own proxy slot and (for Roxy) its own browser window.
    Product files: cpa_auths/xai-<email>.json
    """
    clear_stop()
    px.bind_config(cfg)
    try:
        threads = int(
            concurrency
            if concurrency is not None
            else cfg.get("register_threads", 1)
            or 1
        )
    except (TypeError, ValueError):
        threads = 1
    threads = max(1, min(threads, max(1, count)))

    pool = px.load_proxy_pool(cfg, log=log)
    if cfg.get("use_proxy", True):
        usable = px.available_proxy_pool(pool, cfg, log=log)
        log(
            f"[*] 代理池: {len(pool)} 条 | 可用 {len(usable)} | "
            f"模式 {cfg.get('proxy_pick_mode', 'random')}"
        )
        if usable:
            show = min(len(usable), 8)
            for i, p in enumerate(usable[:show]):
                log(f"[*]   worker-slot {i}: {px.proxy_log_label(p)}")
            if len(usable) > show:
                log(f"[*]   ... 共 {len(usable)} 条可用")
            if threads > len(usable):
                log(
                    f"[!] 并发 {threads} > 可用代理 {len(usable)}，"
                    "部分 worker 会复用同一代理"
                )
        else:
            log("[*] 代理池为空，所有请求直连")
    else:
        log("[*] 代理: 关（直连）")

    try:
        pages_per = max(1, int(cfg.get("browser_pages_per_window") or 3))
    except (TypeError, ValueError):
        pages_per = 3
    browser_windows = (threads + pages_per - 1) // pages_per
    log(
        f"[*] 批量多开: 目标成功数={count} | 并发 worker={threads} "
        f"| 浏览器窗口≈{browser_windows}（每窗 {pages_per} 标签） "
        f"| backend={cfg.get('browser_backend') or 'local'} "
        f"| 复用窗口={bool(cfg.get('turnstile_browser_reuse', True))}"
    )
    log(
        "[*] 计数规则: 仅成功注册计入目标；"
        "Turnstile 失败不消耗尝试上限，会一直补到成功数"
    )
    log(
        f"[*] Turnstile 映射: worker_id → 窗口=worker//{pages_per} "
        f"标签=worker%{pages_per}（过 CF 用对应标签页）"
    )
    if threads <= 1:
        log(
            "[!] 当前并发=1，同一时间只会用 1 个标签页拿 Turnstile。"
            "要批量多开请把「并发」调到 2+（与上个项目「并发线程」相同）。"
        )

    # count = target SUCCESS accounts (not attempts).
    # Turnstile failures never consume max_attempts budget.
    ok = 0
    fail = 0
    ts_fail = 0
    attempts = 0          # total tries (display only)
    counted_attempts = 0  # non-turnstile tries that can hit max_attempts
    results: list[dict] = []
    results_lock = threading.Lock()

    try:
        max_attempts = int(cfg.get("register_max_attempts") or 0)
    except (TypeError, ValueError):
        max_attempts = 0
    if max_attempts <= 0:
        # 0 / unset = unlimited for non-turnstile counted attempts too
        max_attempts = 0

    def _is_turnstile_failure(res: dict) -> bool:
        if res.get("ok"):
            return False
        blob = " ".join(
            str(x or "")
            for x in (
                res.get("error"),
                res.get("result_message"),
                res.get("result_status"),
            )
        ).lower()
        keys = (
            "turnstile",
            "cf-turnstile",
            "failed to verify cloudflare",
            "no turnstile token",
            "cloudflare turnstile",
        )
        return any(k in blob for k in keys)

    def worker(worker_id: int) -> None:
        nonlocal ok, fail, ts_fail, attempts, counted_attempts
        while True:
            if should_stop():
                break
            with results_lock:
                if ok >= count:
                    return
                if max_attempts > 0 and counted_attempts >= max_attempts:
                    return
                attempts += 1
                attempt_no = attempts
                success_so_far = ok
            cap = str(max_attempts) if max_attempts > 0 else "∞"
            log(
                f"\n======== attempt {attempt_no} "
                f"ok={success_so_far}/{count} "
                f"counted={counted_attempts}/{cap} "
                f"(worker {worker_id}) ========"
            )
            try:
                res = register_one(
                    cfg, log=log, worker_id=worker_id, proxy_pool=pool
                )
            except Exception as exc:  # noqa: BLE001
                res = {"ok": False, "error": str(exc)}
                log(f"[!] register failed: {exc}")
            ts_hit = _is_turnstile_failure(res)
            with results_lock:
                results.append(res)
                if res.get("ok"):
                    ok += 1
                    log(
                        json.dumps(
                            {
                                "email": res.get("email"),
                                "password": res.get("password"),
                                "cpa_ok": res.get("cpa_ok"),
                                "cpa_path": res.get("cpa_path"),
                                "cpa_push_ok": res.get("cpa_push_ok"),
                                "proxy": res.get("proxy") or None,
                            },
                            ensure_ascii=False,
                        )
                    )
                    log(
                        f"[+] progress ok={ok}/{count} fail={fail} "
                        f"ts_fail={ts_fail} attempts={attempts}"
                    )
                else:
                    fail += 1
                    if ts_hit:
                        ts_fail += 1
                        # Turnstile failure: do NOT consume max_attempts
                        log(
                            f"[*] progress ok={ok}/{count} fail={fail} "
                            f"ts_fail={ts_fail} attempts={attempts} "
                            f"(turnstile fail ignored by max_attempts)"
                        )
                    else:
                        counted_attempts += 1
                        log(
                            f"[*] progress ok={ok}/{count} fail={fail} "
                            f"ts_fail={ts_fail} counted={counted_attempts}/{cap} "
                            f"attempts={attempts}"
                        )
            if on_result is not None:
                try:
                    on_result(res)
                except Exception:
                    pass
            with results_lock:
                if ok >= count:
                    return
                if max_attempts > 0 and counted_attempts >= max_attempts:
                    return

    workers: list[threading.Thread] = []
    for wid in range(threads):
        t = threading.Thread(
            target=worker, args=(wid,), name=f"reg-{wid}", daemon=True
        )
        workers.append(t)
        t.start()
    for t in workers:
        t.join()

    _cleanup_browsers(cfg, log=log)
    cap = str(max_attempts) if max_attempts > 0 else "∞"
    log(
        f"\ndone ok={ok}/{count} fail={fail} ts_fail={ts_fail} "
        f"attempts={attempts} counted={counted_attempts}/{cap} | 并发={threads}"
    )
    if max_attempts > 0 and counted_attempts >= max_attempts and ok < count:
        log(
            f"[!] 非 Turnstile 尝试已达上限 max_attempts={max_attempts}，"
            f"成功 {ok}/{count}。Turnstile 失败不计入该上限。"
        )
    return 0 if ok >= count else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="xAI protocol register → CPA xai-*.json")
    ap.add_argument(
        "-c",
        "--config",
        default=str(DEFAULT_CONFIG),
        help="config json path",
    )
    ap.add_argument(
        "-n",
        "--count",
        type=int,
        default=None,
        help="how many accounts (skip interactive count if set with --yes)",
    )
    ap.add_argument(
        "-t",
        "--threads",
        type=int,
        default=None,
        help="concurrent workers / browsers (with --yes)",
    )
    ap.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip interactive menu; use config as-is",
    )
    ap.add_argument(
        "--cli",
        action="store_true",
        help="console interactive menu (default when no flags)",
    )
    ap.add_argument(
        "--send-only",
        action="store_true",
        help="only create email + send code + verify (no create user)",
    )
    ap.add_argument(
        "--mint-ledger",
        action="store_true",
        help="mint CPA xai-*.json from accounts.json entries that have sso",
    )
    ap.add_argument(
        "--backend",
        choices=("local", "roxy"),
        default=None,
        help="Turnstile browser backend (overrides config when used with -y)",
    )
    ap.add_argument(
        "--no-proxy",
        action="store_true",
        help="force direct connection (overrides config when used with -y)",
    )
    args = ap.parse_args(argv)
    config_path = Path(args.config)
    cfg = load_config(config_path)
    px.bind_config(cfg)

    if args.mint_ledger:
        from cpa_export import mint_later_from_accounts

        ledger = _resolve_output(Path(str(cfg.get("output_file") or "accounts.json")))
        if not ledger.is_file():
            print(f"[!] ledger missing: {ledger}")
            return 1
        results = mint_later_from_accounts(ledger, config=cfg, log=print)
        ok = sum(1 for r in results if r.get("ok"))
        print(f"\nmint done ok={ok}/{len(results)}")
        return 0 if ok == len(results) and results else 1

    if args.send_only:
        proxy = px.effective_register_proxy(cfg, worker_id=0, log=print) or None
        api_base = str(cfg.get("cloudflare_api_base") or "").rstrip("/")
        api_key = str(cfg.get("cloudflare_api_key") or "")
        domains = cfg.get("default_domains") or ["oo-ooo.fun"]
        domain = domains[0]
        print(f"[send-only] domain={domain} proxy={px.proxy_log_label(proxy or '')}")
        email, jwt = create_address(api_base, api_key, domain=domain)
        print(f"[send-only] email={email}")
        client = AuthClient(
            proxy=proxy,
            log=print,
            connect_timeout=float(cfg.get("proxy_connect_timeout", 12) or 12),
            read_timeout=float(cfg.get("proxy_read_timeout", 25) or 25),
        )
        client.warm()
        client.create_email_validation_code(email)
        code = wait_code(api_base, jwt, api_key, timeout=120, log=print)
        print(f"[send-only] code={code}")
        client.verify_email_validation_code(email, code)
        print("[send-only] verify OK")
        return 0

    # Console only (GUI fully removed).
    if not args.yes:
        cfg = interactive_menu(cfg, config_path)
        count = int(cfg.get("register_count") or 1)
        threads = int(cfg.get("register_threads") or 1)
    else:
        if args.backend:
            cfg["browser_backend"] = args.backend
        if args.no_proxy:
            cfg["use_proxy"] = False
        try:
            count = int(
                args.count if args.count is not None else cfg.get("register_count", 1)
            )
        except (TypeError, ValueError):
            count = 1
        count = max(1, count)
        try:
            threads = int(
                args.threads
                if args.threads is not None
                else cfg.get("register_threads", 1)
                or 1
            )
        except (TypeError, ValueError):
            threads = 1
        threads = max(1, min(threads, count))
        cfg["register_threads"] = threads

    return run_batch(cfg, count, concurrency=threads)


if __name__ == "__main__":
    sys.exit(main())
