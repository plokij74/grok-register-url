"""Register hook: SSO cookie → OIDC mint → write CPA xai-<email>.json.

Reuses protocol mint from sibling grok_reg-protocol_cpa (same venv).
Primary product file matches CLIProxyAPI TokenStorage (reference project).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Callable

from cpa_schema import DEFAULT_BASE_URL, build_cpa_xai_auth, credential_file_name
from cpa_writer import write_cpa_xai_auth

def _push_to_remote(
    file_path: Path,
    base_url: str,
    api_key: str,
    log: Callable,
    *,
    retries: int = 3,
    timeout: float = 30.0,
) -> dict:
    """Push xai-*.json to remote CLIProxyAPI with retries.

    Returns {ok, attempts, error?, url?, name}.
    """
    import json as _json
    import urllib.error
    import urllib.request

    name = file_path.name
    url = f"{base_url.rstrip('/')}/v0/management/auth-files?name={name}"
    data = file_path.read_bytes()
    attempts = max(1, int(retries or 1))
    last_err = ""

    for i in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "GrokX/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
                body = resp.read().decode("utf-8", "replace")
                result = _json.loads(body) if body.strip() else {}
            if result.get("status") == "ok":
                log(
                    f"[cpa] 已推送到远程 CPA: {url.split('?')[0]} "
                    f"({name}) attempt={i}/{attempts}"
                )
                return {
                    "ok": True,
                    "attempts": i,
                    "url": url.split("?")[0],
                    "name": name,
                }
            last_err = f"远程 CPA 返回: {result}"
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except Exception:
                detail = ""
            last_err = f"HTTP {exc.code}: {detail or exc.reason}"
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"

        if i < attempts:
            wait = min(8.0, 1.0 * i)
            log(
                f"[cpa] 推送失败 attempt={i}/{attempts} ({name}): {last_err} "
                f"→ {wait:.0f}s 后重试"
            )
            time.sleep(wait)
        else:
            log(f"[cpa] 推送到远程 CPA 失败 ({name}) after {attempts} attempts: {last_err}")

    return {
        "ok": False,
        "attempts": attempts,
        "error": last_err or "push failed",
        "url": url.split("?")[0],
        "name": name,
    }


ROOT = Path(__file__).resolve().parent

# Sibling package has pure-HTTP SSO → device-code mint
_SIBLING = Path(__file__).resolve().parent  # vendored ./cpa_xai
if _SIBLING.is_dir() and str(_SIBLING) not in sys.path:
    sys.path.insert(0, str(_SIBLING))


def _resolve_auth_dir(cfg: dict) -> Path:
    raw = str(cfg.get("cpa_auth_dir") or "cpa_auths").strip()
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (ROOT / p).resolve()
    return p


def _record_failure(out_dir: Path, email: str, reason: str) -> None:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "cpa_auth_failed.txt", "a", encoding="utf-8") as f:
            f.write(f"{email}----{reason}----{int(time.time())}\n")
    except Exception:
        pass


def _mint_proxy_candidates(cfg: dict, log=None) -> list[str | None]:
    """Build ordered proxy list for CPA mint retries.

    mint_proxy (if set) first, then worker proxy, then other pool IPs,
    then local config.proxy, finally direct.

    Each non-empty entry is passed through apply_local_chain so 711/rotgb
    etc. become http://127.0.0.1:<bridge> via Clash.
    """
    try:
        import proxyutil as px
    except Exception:
        mp = str(cfg.get("mint_proxy") or cfg.get("proxy") or "").strip() or None
        return [mp]

    worker = str(cfg.get("_worker_proxy") or "").strip() or None
    explicit = str(cfg.get("mint_proxy") or "").strip() or None
    local = px.normalize_proxy_url(cfg.get("proxy") or "") or None
    _log = log or (lambda _m: None)

    ordered: list[str | None] = []
    seen: set[str] = set()

    def _add(p: str | None) -> None:
        if not p:
            return
        # identity on original residential (before bridge rewrite)
        key = px.proxy_identity(p) or p
        if key in seen:
            return
        seen.add(key)
        client = px.apply_local_chain(p, cfg, log=_log) or p
        ordered.append(client)

    if explicit:
        _add(px.normalize_proxy_url(explicit) or explicit)
    _add(px.normalize_proxy_url(worker) if worker else None)

    try:
        pool = px.available_proxy_pool(cfg=cfg, log=lambda _m: None)
    except Exception:
        pool = []
    # shuffle-ish: prefer unused hosts first (stable order is fine)
    for p in pool:
        _add(p)

    _add(local)
    # last resort: direct (no proxy) — SSO cookie still valid from any exit
    ordered.append(None)
    return ordered


def _is_retryable_mint_error(msg: str) -> bool:
    m = (msg or "").lower()
    keys = (
        "network error",
        "connection was reset",
        "recv failure",
        "timed out",
        "timeout",
        "curl: (28)",
        "curl: (35)",
        "curl: (56)",
        "curl: (97)",
        "curl: (7)",
        "proxy",
        "socks",
        "ssl",
        "handshake",
        "failed to perform",
        "device code:",
        "verification_uri",
        "accounts.x.ai",
    )
    # do not retry hard auth failures
    hard = ("sso invalid", "missing sso", "empty sso", "access_denied", "expired_token")
    if any(h in m for h in hard):
        return False
    return any(k in m for k in keys)


def export_cpa_from_sso(
    *,
    email: str,
    sso: str,
    password: str = "",
    config: dict | None = None,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Mint OIDC from session SSO cookie and write xai-<email>.json.

    Returns {ok, email, path?, payload?, error?, skipped?}.
    On transient proxy/TLS errors, rotates mint proxy (pool + local + direct).
    """
    cfg = config or {}
    log = log or (lambda m: print(m, flush=True))
    email = (email or "").strip()
    sso = (sso or "").strip()

    if not cfg.get("cpa_export_enabled", True):
        log("[cpa] export disabled, skip")
        return {"ok": False, "skipped": True, "reason": "disabled", "email": email}
    if not email:
        return {"ok": False, "error": "missing email"}
    if not sso:
        log("[cpa] no sso cookie — cannot mint OIDC yet")
        return {"ok": False, "error": "no sso", "email": email}

    out_dir = _resolve_auth_dir(cfg)
    timeout = float(cfg.get("mint_timeout_sec") or 90)
    base_url = str(cfg.get("cpa_base_url") or DEFAULT_BASE_URL)

    try:
        from cpa_xai.protocol_mint import ProtocolMintError, mint_with_sso_protocol
    except ImportError as exc:
        msg = f"protocol_mint import failed: {exc}"
        log(f"[cpa] {msg}")
        _record_failure(out_dir, email, msg)
        return {"ok": False, "error": msg, "email": email}

    try:
        import proxyutil as px

        candidates = _mint_proxy_candidates(cfg, log=log)
        label_fn = px.proxy_log_label
    except Exception:
        candidates = [
            str(cfg.get("mint_proxy") or cfg.get("_worker_proxy") or cfg.get("proxy") or "").strip()
            or None
        ]
        label_fn = lambda p: p or "(direct)"  # noqa: E731

    # cap attempts so mint doesn't hang forever
    try:
        max_try = int(cfg.get("mint_proxy_retries") or 0)
    except (TypeError, ValueError):
        max_try = 0
    if max_try <= 0:
        max_try = min(6, max(3, len([c for c in candidates if c is not None]) + 1))
    candidates = candidates[:max_try]

    log(f"[cpa] mint SSO→OIDC email={email} attempts={len(candidates)}")
    last_err = ""
    tokens: dict[str, Any] | None = None
    for i, proxy in enumerate(candidates):
        tag = label_fn(proxy) if proxy else "(direct)"
        log(f"[cpa] mint attempt {i + 1}/{len(candidates)} proxy={tag}")
        try:
            tokens = mint_with_sso_protocol(
                sso_cookie=sso,
                email=email,
                proxy=proxy,
                timeout=min(timeout, 45.0),
                poll_timeout_sec=timeout,
                log=lambda m: log(f"[cpa] {m}"),
            )
            last_err = ""
            break
        except ProtocolMintError as exc:
            last_err = str(exc)
            log(f"[cpa] mint failed ({tag}): {last_err}")
            if not _is_retryable_mint_error(last_err) or i + 1 >= len(candidates):
                break
            continue
        except Exception as exc:  # noqa: BLE001
            last_err = f"mint exception: {exc}"
            log(f"[cpa] {last_err} ({tag})")
            if not _is_retryable_mint_error(last_err) or i + 1 >= len(candidates):
                break
            continue

    if not tokens:
        msg = last_err or "mint failed"
        _record_failure(out_dir, email, msg)
        return {"ok": False, "error": msg, "email": email}

    access = str(tokens.get("access_token") or "").strip()
    refresh = str(tokens.get("refresh_token") or "").strip()
    if not access or not refresh:
        msg = "mint returned empty access/refresh"
        log(f"[cpa] {msg}")
        _record_failure(out_dir, email, msg)
        return {"ok": False, "error": msg, "email": email}

    try:
        payload = build_cpa_xai_auth(
            email=email,
            access_token=access,
            refresh_token=refresh,
            id_token=tokens.get("id_token"),
            expires_in=tokens.get("expires_in"),
            base_url=base_url,
        )
        # Keep password in a side field only if requested (not part of CPA TokenStorage)
        if password and cfg.get("cpa_include_password", False):
            payload["password"] = password
        path = write_cpa_xai_auth(out_dir, payload)
    except Exception as exc:  # noqa: BLE001
        msg = f"write failed: {exc}"
        log(f"[cpa] {msg}")
        _record_failure(out_dir, email, msg)
        return {"ok": False, "error": msg, "email": email}

    log(f"[cpa] wrote {path.name} → {path}")

    push_info: dict[str, Any] = {"ok": False, "skipped": True, "reason": "disabled"}
    # 推送到远程 CPA (CLIProxyAPI)
    if cfg.get("cpa_push_enabled", False):
        push_base = str(cfg.get("cpa_push_base_url", "") or "").strip().rstrip("/")
        push_key = str(cfg.get("cpa_push_api_key", "") or "").strip()
        if push_base and push_key:
            try:
                retries = int(cfg.get("cpa_push_retries", 3) or 3)
            except (TypeError, ValueError):
                retries = 3
            try:
                push_timeout = float(cfg.get("cpa_push_timeout_sec", 30) or 30)
            except (TypeError, ValueError):
                push_timeout = 30.0
            push_info = _push_to_remote(
                path,
                push_base,
                push_key,
                log,
                retries=max(1, retries),
                timeout=max(5.0, push_timeout),
            )
        else:
            push_info = {
                "ok": False,
                "skipped": True,
                "reason": "missing cpa_push_base_url/cpa_push_api_key",
            }
            log("[cpa] cpa_push_base_url/cpa_push_api_key 未配置，跳过推送")
    else:
        log("[cpa] push disabled, skip remote upload")

    return {
        "ok": True,
        "email": email,
        "path": str(path),
        "filename": path.name,
        "sub": payload.get("sub"),
        "payload": payload,
        "cpa_push_ok": bool(push_info.get("ok")),
        "cpa_push": push_info,
    }


def mint_later_from_accounts(
    accounts_path: Path,
    *,
    config: dict | None = None,
    log: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Batch mint CPA files for accounts.json entries that have sso."""
    import json

    cfg = config or {}
    log = log or (lambda m: print(m, flush=True))
    raw = json.loads(accounts_path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    results = []
    for it in items:
        if not isinstance(it, dict):
            continue
        email = str(it.get("email") or "")
        sso = str(it.get("sso") or "")
        if not email or not sso:
            continue
        # skip if already written
        out_dir = _resolve_auth_dir(cfg)
        existing = out_dir / credential_file_name(email)
        if existing.is_file() and not cfg.get("cpa_force_remint", False):
            log(f"[cpa] skip existing {existing.name}")
            results.append({"ok": True, "skipped": True, "email": email, "path": str(existing)})
            continue
        results.append(
            export_cpa_from_sso(
                email=email,
                sso=sso,
                password=str(it.get("password") or ""),
                config=cfg,
                log=log,
            )
        )
    return results
