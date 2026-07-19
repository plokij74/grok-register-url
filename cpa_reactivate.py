#!/usr/bin/env python3
"""Scan remote CPA xai auth files, refresh or remint expired/dead ones, re-push.

Typical dead signals on remote CLIProxyAPI:
  - local/remote access token expired field is past now
  - remote failed > 0 / missing last_refresh (auto-refresh workers stuck)
  - refresh_token grant returns invalid_grant (revoked)

Recovery order per account:
  1) OAuth refresh_token grant (fast)
  2) Protocol remint: browser ONLY for CF Turnstile token
     → HTTP CreateSession(email/password + turnstile) → SSO cookie
     → SSO protocol device-flow mint → write xai-*.json
  3) POST updated xai-*.json back to CPA

Same CF pattern as register_protocol.py (turnstile_browser / CapSolver),
NOT full browser login UI.

Examples:
  .venv/bin/python cpa_reactivate.py --dry-run
  .venv/bin/python cpa_reactivate.py --limit 20 --workers 3
  .venv/bin/python cpa_reactivate.py --min-failed 1 --workers 4
  .venv/bin/python cpa_reactivate.py --email foo@bar.com
  .venv/bin/python cpa_reactivate.py --local-only --expired --limit 50
  .venv/bin/python cpa_reactivate.py --disabled --dry-run
  .venv/bin/python cpa_reactivate.py --from-inspection reauth --dry-run
  .venv/bin/python cpa_reactivate.py --from-inspection reauth --headed --workers 1
  .venv/bin/python cpa_reactivate.py --workers 1 --headed --limit 5
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpa_export import _push_to_remote  # noqa: E402
from cpa_schema import CLIENT_ID, TOKEN_ENDPOINT, build_cpa_xai_auth  # noqa: E402
from cpa_writer import write_cpa_xai_auth  # noqa: E402

LogFn = Callable[[str], None]
_print_lock = threading.Lock()


def _log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def _load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_ts(value: str | None) -> datetime | None:
    s = (value or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.strptime(s.replace("Z", "+0000").replace("+00:00", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
        except Exception:
            return None


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _email_from_name(name: str) -> str:
    n = (name or "").strip()
    if n.startswith("xai-") and n.endswith(".json"):
        return n[len("xai-") : -len(".json")]
    return n


def _auth_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "GrokX/1.0",
    }


def _http_json(
    url: str,
    *,
    api_key: str,
    method: str = "GET",
    data: bytes | None = None,
    timeout: float = 60.0,
) -> Any:
    headers = _auth_headers(api_key)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:400]
        except Exception:
            detail = str(exc.reason)
        raise RuntimeError(f"HTTP {exc.code} {url}: {detail}") from exc


def list_remote_auth_files(base_url: str, api_key: str, timeout: float = 60.0) -> list[dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/v0/management/auth-files"
    data = _http_json(url, api_key=api_key, timeout=timeout)
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, list):
        raise RuntimeError(f"unexpected auth-files response: {type(data)}")
    return [f for f in files if isinstance(f, dict)]


def fetch_inspection_status(
    base_url: str,
    api_key: str,
    *,
    include_results: bool = True,
    timeout: float = 90.0,
) -> dict[str, Any]:
    """GET grok-inspection plugin status (CPAMP 巡检)."""
    q = "include_results=1" if include_results else ""
    url = f"{base_url.rstrip('/')}/v0/management/plugins/grok-inspection/status"
    if q:
        url = f"{url}?{q}"
    data = _http_json(url, api_key=api_key, timeout=timeout)
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected grok-inspection status response: {type(data)}")
    return data


def _parse_inspection_classes(raw: str) -> set[str]:
    """Comma-separated classifications, default reauth if empty/true-like."""
    s = (raw or "").strip().lower()
    if not s or s in {"1", "true", "yes", "on"}:
        return {"reauth"}
    out = {p.strip().lower() for p in s.split(",") if p.strip()}
    return out or {"reauth"}


def collect_inspection_targets(
    *,
    base_url: str,
    api_key: str,
    classes: set[str],
    remote_index: dict[str, dict[str, Any]] | None = None,
    timeout: float = 90.0,
    log: LogFn | None = None,
) -> list[dict[str, Any]]:
    """Build targets from grok-inspection results filtered by classification.

    Real 需重登 = classification reauth. NOT CPA disabled / quota_exhausted.
    """
    log = log or _log
    data = fetch_inspection_status(base_url, api_key, include_results=True, timeout=timeout)
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    log(
        f"[*] inspection summary={summary} finished_at={data.get('finished_at')} "
        f"running={data.get('running')}"
    )
    results = data.get("results") if isinstance(data.get("results"), list) else []
    want = {c.lower() for c in classes}
    remote_index = remote_index or {}
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for x in results:
        if not isinstance(x, dict):
            continue
        cls = str(x.get("classification") or "").strip().lower()
        if cls not in want:
            continue
        name = str(x.get("file_name") or x.get("name") or x.get("id") or "").strip()
        email = str(x.get("email") or x.get("account") or "").strip()
        if not name and email:
            name = f"xai-{email}.json"
        if not name:
            continue
        if not name.endswith(".json") and "@" in name:
            name = f"xai-{name}.json"
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        if not email:
            email = _email_from_name(name)
        meta = remote_index.get(name) or remote_index.get(name.lower())
        if meta is None and email:
            meta = remote_index.get(email.lower())
        reason = f"inspection:{cls}"
        extra = str(x.get("reason") or "").strip()
        if extra:
            reason = f"{reason}:{extra[:80]}"
        targets.append(
            {
                "name": name,
                "email": email,
                "remote_meta": meta if isinstance(meta, dict) else None,
                "reason": reason,
                "inspection": {
                    "classification": cls,
                    "disabled": x.get("disabled"),
                    "action": x.get("action"),
                    "reason": x.get("reason"),
                    "http_status": x.get("http_status"),
                    "error_code": x.get("error_code"),
                },
            }
        )
    log(f"[*] inspection classes={sorted(want)} matched={len(targets)} (of results={len(results)})")
    return targets


def download_remote_auth(
    base_url: str,
    api_key: str,
    name: str,
    timeout: float = 45.0,
) -> dict[str, Any]:
    q = urllib.parse.urlencode({"name": name})
    url = f"{base_url.rstrip('/')}/v0/management/auth-files/download?{q}"
    data = _http_json(url, api_key=api_key, timeout=timeout)
    if not isinstance(data, dict) or not data.get("refresh_token"):
        raise RuntimeError(f"download missing refresh_token for {name}")
    return data


def load_local_auth(auth_dir: Path, name: str) -> dict[str, Any] | None:
    p = auth_dir / name
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def load_accounts_map(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else [raw]
    out: dict[str, dict[str, Any]] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        email = str(it.get("email") or "").strip()
        if email:
            out[email] = it
    return out


def _post_refresh(
    refresh_token: str,
    *,
    proxy: str | None,
    timeout: float = 30.0,
    client_id: str = CLIENT_ID,
) -> dict[str, Any]:
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    # Prefer curl_cffi (same fingerprint path as mint)
    try:
        from curl_cffi import requests as cf_requests

        proxies = {"http": proxy, "https": proxy} if proxy else None
        r = cf_requests.post(
            TOKEN_ENDPOINT,
            data=form,
            proxies=proxies,  # type: ignore[arg-type]
            timeout=timeout,
            impersonate="chrome131",
            allow_redirects=True,
        )
        status = int(getattr(r, "status_code", 0) or 0)
        text = getattr(r, "text", "") or ""
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = {"raw": text}
        return {"status": status, "body": body}
    except ImportError:
        pass

    import urllib.parse as up

    data = up.urlencode(form).encode("utf-8")
    handlers: list[Any] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()
    req = urllib.request.Request(
        TOKEN_ENDPOINT,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "GrokX-reactivate/1.0",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
            status = int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        status = int(exc.code)
    try:
        body = json.loads(text)
    except json.JSONDecodeError:
        body = {"raw": text}
    return {"status": status, "body": body}


def try_refresh_payload(
    payload: dict[str, Any],
    *,
    proxy: str | None,
    base_url: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Return {ok, payload?, error?, revoked?}."""
    refresh = str(payload.get("refresh_token") or "").strip()
    email = str(payload.get("email") or "").strip()
    if not refresh:
        return {"ok": False, "error": "missing refresh_token", "revoked": False}
    res = _post_refresh(refresh, proxy=proxy, timeout=timeout)
    status = int(res.get("status") or 0)
    body_raw = res.get("body")
    body: dict[str, Any] = body_raw if isinstance(body_raw, dict) else {}
    if status == 200 and body.get("access_token"):
        access = str(body["access_token"]).strip()
        new_refresh = str(body.get("refresh_token") or refresh).strip()
        built = build_cpa_xai_auth(
            email=email or str(payload.get("email") or ""),
            access_token=access,
            refresh_token=new_refresh,
            id_token=body.get("id_token") or payload.get("id_token"),
            expires_in=body.get("expires_in"),
            base_url=str(payload.get("base_url") or base_url),
            token_endpoint=str(payload.get("token_endpoint") or TOKEN_ENDPOINT),
            redirect_uri=str(payload.get("redirect_uri") or "http://127.0.0.1:56121/callback"),
            sub=str(payload.get("sub") or "") or None,
        )
        # preserve disabled flag if present on remote payload
        if "disabled" in payload:
            built["disabled"] = payload.get("disabled")
        return {"ok": True, "payload": built, "method": "refresh"}
    err = ""
    if body:
        err = f"{body.get('error') or ''}: {body.get('error_description') or body}"
    else:
        err = str(body_raw)
    revoked = "revoked" in err.lower() or "invalid_grant" in err.lower()
    return {"ok": False, "error": err or f"HTTP {status}", "revoked": revoked, "status": status}


def is_expired_payload(payload: dict[str, Any] | None, now: datetime | None = None) -> bool:
    if not payload:
        return False
    now = now or _now()
    exp = _parse_ts(str(payload.get("expired") or ""))
    if exp is None:
        return False
    return exp <= now


def _payload_disabled(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    return bool(payload.get("disabled"))


def needs_reactivation(
    *,
    remote_meta: dict[str, Any] | None,
    local_payload: dict[str, Any] | None,
    remote_payload: dict[str, Any] | None,
    min_failed: int,
    expired_only: bool,
    disabled_only: bool = False,
    include_ok: bool,
    stale_hours: float = 6.0,
) -> tuple[bool, str]:
    """Decide whether this auth should be processed. Returns (need, reason)."""
    now = _now()
    reasons: list[str] = []

    failed = int((remote_meta or {}).get("failed") or 0)
    success = int((remote_meta or {}).get("success") or 0)
    last_refresh = (remote_meta or {}).get("last_refresh")
    disabled = bool((remote_meta or {}).get("disabled")) or _payload_disabled(local_payload) or _payload_disabled(
        remote_payload
    )
    unavailable = bool((remote_meta or {}).get("unavailable"))
    status = str((remote_meta or {}).get("status") or "").lower()

    if disabled:
        reasons.append("disabled")
    if unavailable:
        reasons.append("unavailable")
    if status and status not in {"active", "ok", ""}:
        reasons.append(f"status={status}")
    # CPA keeps historical failed counters after re-push; only treat as dead when
    # token is stale / missing last_refresh / unavailable, not merely failed>0.
    lr_dt = _parse_ts(str(last_refresh or ""))
    lr_age_h = ((now - lr_dt).total_seconds() / 3600.0) if lr_dt else None
    token_expired = is_expired_payload(local_payload, now) or is_expired_payload(remote_payload, now)
    if remote_meta is not None and not last_refresh:
        reasons.append("no_last_refresh")
    elif lr_age_h is not None and lr_age_h >= float(stale_hours) and failed >= max(1, min_failed):
        reasons.append(f"stale_refresh={lr_age_h:.1f}h,failed={failed}")
    if token_expired and failed >= max(0, min_failed):
        if failed:
            reasons.append(f"failed={failed}")

    if is_expired_payload(local_payload, now):
        reasons.append("local_expired")
    if is_expired_payload(remote_payload, now):
        reasons.append("remote_expired")

    # hard dead signals always win
    hard = {"disabled", "unavailable", "no_last_refresh", "local_expired", "remote_expired"}
    hard_hit = [r for r in reasons if r in hard or r.startswith("status=") or r.startswith("stale_refresh=")]

    if include_ok:
        return True, "include_ok"

    if disabled_only:
        if "disabled" in reasons:
            return True, ",".join(reasons)
        return False, "not_disabled"

    if expired_only:
        if any(r in reasons for r in ("local_expired", "remote_expired")):
            return True, ",".join(reasons)
        return False, "not_expired"

    if hard_hit:
        # attach soft counters for logs
        soft = []
        if failed:
            soft.append(f"failed={failed}")
        if success == 0 and failed:
            soft.append("success=0")
        return True, ",".join(hard_hit + soft)
    return False, "healthy"


def resolve_proxy(cfg: dict[str, Any]) -> str | None:
    raw = str(cfg.get("mint_proxy") or cfg.get("proxy") or "").strip()
    return raw or None


def process_one(
    *,
    name: str,
    email: str,
    remote_meta: dict[str, Any] | None,
    cfg: dict[str, Any],
    auth_dir: Path,
    accounts: dict[str, dict[str, Any]],
    args: argparse.Namespace,
    log: LogFn,
    worker_id: int = 0,
    seed_reason: str | None = None,
) -> dict[str, Any]:
    base = str(cfg.get("cpa_push_base_url") or "").rstrip("/")
    key = str(cfg.get("cpa_push_api_key") or "").strip()
    cpa_base = str(cfg.get("cpa_base_url") or "https://cli-chat-proxy.grok.com/v1")
    proxy = resolve_proxy(cfg)
    local = load_local_auth(auth_dir, name)

    remote_payload: dict[str, Any] | None = None
    if not args.local_only and not args.dry_run and base and key:
        try:
            remote_payload = download_remote_auth(base, key, name, timeout=float(args.timeout))
        except Exception as exc:  # noqa: BLE001
            if local is None:
                return {
                    "ok": False,
                    "name": name,
                    "email": email,
                    "error": f"download failed and no local: {exc}",
                }
            log(f"[!] {name}: download failed ({exc}); fall back to local")

    from_inspection = bool(getattr(args, "from_inspection", None))
    need, reason = needs_reactivation(
        remote_meta=remote_meta,
        local_payload=local,
        remote_payload=remote_payload,
        min_failed=int(args.min_failed),
        expired_only=bool(args.expired),
        disabled_only=bool(args.disabled),
        include_ok=bool(args.all),
        stale_hours=float(args.stale_hours),
    )
    # --email / --from-inspection already selected targets; always process them
    if args.email or from_inspection:
        if seed_reason:
            reason = seed_reason
        elif not need:
            reason = "forced_email" if args.email else "inspection_forced"
        need = True
    if not need:
        return {
            "ok": True,
            "skipped": True,
            "name": name,
            "email": email,
            "reason": reason,
        }

    source_payload = remote_payload or local
    if source_payload is None:
        return {"ok": False, "name": name, "email": email, "error": "no local/remote payload"}

    result: dict[str, Any] = {
        "ok": False,
        "name": name,
        "email": email,
        "reason": reason,
        "method": None,
    }

    if args.dry_run:
        would = "refresh"
        if not args.refresh_only:
            if args.no_browser:
                would += "→(stop)"
            else:
                would += "→protocol_cf_login"
        result.update({"ok": True, "dry_run": True, "would": would})
        return result

    # 1) refresh
    if not args.remint_only:
        ref = try_refresh_payload(
            source_payload,
            proxy=proxy,
            base_url=cpa_base,
            timeout=float(args.timeout),
        )
        if ref.get("ok"):
            payload = ref["payload"]
            path = write_cpa_xai_auth(auth_dir, payload, filename=name)
            result.update(
                {
                    "ok": True,
                    "method": "refresh",
                    "path": str(path),
                    "expired": payload.get("expired"),
                }
            )
            if cfg.get("cpa_push_enabled", True) and not args.no_push and base and key:
                push = _push_to_remote(
                    path,
                    base,
                    key,
                    log,
                    retries=int(cfg.get("cpa_push_retries") or 3),
                    timeout=float(cfg.get("cpa_push_timeout_sec") or 30),
                )
                result["cpa_push_ok"] = bool(push.get("ok"))
                result["cpa_push"] = push
            else:
                result["cpa_push_ok"] = False
                result["cpa_push"] = {"skipped": True}
            return result
        result["refresh_error"] = ref.get("error")
        if args.refresh_only:
            result["error"] = ref.get("error") or "refresh failed"
            return result
        if not ref.get("revoked") and not args.force_remint:
            # unknown refresh error — still try remint unless hard-stopped
            log(f"[!] {name}: refresh failed ({ref.get('error')}); try protocol login")

    # 2) protocol remint: browser ONLY for Turnstile, then CreateSession + SSO mint
    acc = accounts.get(email) or {}
    password = str(acc.get("password") or "").strip()
    errors: list[str] = []
    if result.get("refresh_error"):
        errors.append(f"refresh: {result['refresh_error']}")

    allow_browser = not args.no_browser and not args.refresh_only
    if allow_browser and not password:
        errors.append("protocol: no password")
        allow_browser = False

    if allow_browser:
        br = remint_with_protocol_cf(
            email=email,
            password=password,
            cfg=cfg,
            auth_dir=auth_dir,
            proxy=proxy,
            base_url=cpa_base,
            name=name,
            args=args,
            log=lambda m: log(f"[{email}] {m}"),
            worker_id=int(worker_id or 0),
        )
        if br.get("ok"):
            path_s = str(br.get("path") or "")
            path = Path(path_s) if path_s else auth_dir / name
            # ensure filename matches CPA id even if writer used email form
            if path.is_file() and path.name != name:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    path = write_cpa_xai_auth(auth_dir, payload, filename=name)
                except Exception as exc:  # noqa: BLE001
                    log(f"[!] {name}: rename/write after protocol mint: {exc}")
            result.update(
                {
                    "ok": True,
                    "method": "protocol",
                    "path": str(path),
                    "expired": br.get("expired"),
                    "mint_method": br.get("mint_method"),
                }
            )
            if cfg.get("cpa_push_enabled", True) and not args.no_push and base and key and path.is_file():
                push = _push_to_remote(
                    path,
                    base,
                    key,
                    log,
                    retries=int(cfg.get("cpa_push_retries") or 3),
                    timeout=float(cfg.get("cpa_push_timeout_sec") or 30),
                )
                result["cpa_push_ok"] = bool(push.get("ok"))
                result["cpa_push"] = push
            else:
                result["cpa_push_ok"] = False
                result["cpa_push"] = {"skipped": True}
            return result
        errors.append(f"protocol: {br.get('error') or 'failed'}")
        result["protocol"] = br

    result["error"] = " | ".join(errors) if errors else (result.get("refresh_error") or "remint failed")
    return result


def remint_with_protocol_cf(
    *,
    email: str,
    password: str,
    cfg: dict[str, Any],
    auth_dir: Path,
    proxy: str | None,
    base_url: str,
    name: str,
    args: argparse.Namespace,
    log: LogFn,
    worker_id: int = 0,
) -> dict[str, Any]:
    """Login via HTTP CreateSession; browser only solves CF Turnstile (same as register).

    Flow:
      1. solve_turnstile (turnstile_browser / CapSolver / config token)
      2. AuthClient.create_session(email, password, turnstile)
      3. extract SSO cookie
      4. export_cpa_from_sso → write cpa_auths (push done by caller)
    """
    try:
        from auth_client import AuthClient, AuthError, extract_session_cookie
        from cpa_export import export_cpa_from_sso
        from register_protocol import solve_turnstile
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"import protocol deps: {exc}"}

    # headed/headless only affects Turnstile browser seat (not full login UI)
    cfg_ts = dict(cfg)
    if bool(getattr(args, "headed", False)):
        cfg_ts["turnstile_headless"] = False
    elif bool(getattr(args, "headless", False)):
        cfg_ts["turnstile_headless"] = True

    try:
        connect_to = float(cfg.get("proxy_connect_timeout", 12) or 12)
        read_to = float(cfg.get("proxy_read_timeout", 25) or 25)
    except (TypeError, ValueError):
        connect_to, read_to = 12.0, 25.0

    wid = int(worker_id or getattr(args, "_worker_id", 0) or 0)
    log(
        f"[cpa] protocol CF remint email={email} headless={bool(cfg_ts.get('turnstile_headless'))} "
        f"proxy={proxy or '(none)'} worker={wid}"
    )

    # 1) Turnstile only (register path)
    try:
        turnstile = solve_turnstile(cfg_ts, log, proxy=proxy, worker_id=wid)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"turnstile solve: {exc}"}
    if not turnstile:
        return {
            "ok": False,
            "error": "no turnstile token — set capsolver_api_key / turnstile_token "
            "or fix browser solver (local/roxy)",
        }
    log(f"[cpa] turnstile ok len={len(str(turnstile))}")

    # 2) HTTP CreateSession
    client = AuthClient(
        proxy=proxy,
        log=log,
        connect_timeout=connect_to,
        read_timeout=read_to,
    )
    try:
        client.warm_sign_in()
    except Exception as exc:  # noqa: BLE001
        log(f"[cpa] warm sign-in soft fail: {exc}")

    try:
        result = client.create_session(
            email=email,
            password=password,
            turnstile_token=str(turnstile),
            use_v2=True,
        )
    except AuthError as exc:
        return {"ok": False, "error": f"CreateSession: {exc}", "turnstile_used": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"CreateSession exception: {exc}", "turnstile_used": True}

    frames = (result or {}).get("frames") or []
    sso = ""
    try:
        sso = client.get_sso() or extract_session_cookie(frames)
    except Exception as exc:  # noqa: BLE001
        log(f"[cpa] extract sso: {exc}")
    if not sso:
        return {
            "ok": False,
            "error": "CreateSession ok but no sso cookie",
            "turnstile_used": True,
            "result_status": (result or {}).get("status"),
            "result_message": (result or {}).get("message"),
        }
    log(f"[cpa] CreateSession ok sso_len={len(sso)}")

    # 3) SSO → OIDC mint (same as register export)
    cfg_mint = dict(cfg)
    cfg_mint["_worker_proxy"] = proxy or ""
    # caller handles push; avoid double-push here
    cfg_mint["cpa_push_enabled"] = False
    cfg_mint["cpa_export_enabled"] = True
    cfg_mint["cpa_force_remint"] = True
    if auth_dir:
        try:
            cfg_mint["cpa_auth_dir"] = str(auth_dir)
        except Exception:
            pass

    mint = export_cpa_from_sso(
        email=email,
        sso=sso,
        password=password,
        config=cfg_mint,
        log=log,
    )
    if not mint.get("ok"):
        return {
            "ok": False,
            "error": mint.get("error") or "SSO mint failed",
            "turnstile_used": True,
            "sso": True,
        }

    path = str(mint.get("path") or "")
    # normalize filename to CPA id
    if path and name and Path(path).name != name:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            path = str(write_cpa_xai_auth(auth_dir, payload, filename=name))
        except Exception as exc:  # noqa: BLE001
            log(f"[cpa] filename normalize: {exc}")

    expired = None
    if path:
        try:
            expired = json.loads(Path(path).read_text(encoding="utf-8")).get("expired")
        except Exception:
            expired = None
    return {
        "ok": True,
        "path": path,
        "expired": expired,
        "mint_method": "protocol_create_session",
        "turnstile_used": True,
        "sso": True,
    }


def collect_targets(
    *,
    cfg: dict[str, Any],
    auth_dir: Path,
    args: argparse.Namespace,
    log: LogFn,
) -> list[dict[str, Any]]:
    """Return list of {name,email,remote_meta}."""
    targets: list[dict[str, Any]] = []
    base = str(cfg.get("cpa_push_base_url") or "").rstrip("/")
    key = str(cfg.get("cpa_push_api_key") or "").strip()
    insp_raw = getattr(args, "from_inspection", None)
    insp_classes = _parse_inspection_classes(str(insp_raw)) if insp_raw is not None else set()

    if args.local_only:
        if insp_classes:
            raise SystemExit("--from-inspection cannot be combined with --local-only")
        names = sorted(p.name for p in auth_dir.glob("xai-*.json"))
        for name in names:
            email = _email_from_name(name)
            if args.email and email != args.email and name != args.email:
                continue
            local = load_local_auth(auth_dir, name)
            need = False
            reason = "not_expired"
            if args.email:
                need = True
                reason = "forced_email"
            elif args.all:
                need = True
                reason = "include_ok"
            elif args.disabled:
                need = _payload_disabled(local)
                reason = "disabled" if need else "not_disabled"
            else:
                need = is_expired_payload(local)
                reason = "local_expired" if need else "not_expired"
            if not need:
                continue
            targets.append({"name": name, "email": email, "remote_meta": None, "reason": reason})
        return targets

    if not base or not key:
        raise SystemExit("cpa_push_base_url / cpa_push_api_key required (or use --local-only)")

    # 巡检 reauth / 其它 classification：只取 grok-inspection 结果，不走 auth-files hard-dead
    if insp_classes:
        if args.disabled or args.expired or args.all:
            log("[!] --from-inspection ignores --disabled/--expired/--all (inspection is the filter)")
        remote_index: dict[str, dict[str, Any]] = {}
        try:
            log(f"[*] listing remote auth-files from {base} (index for inspection targets)")
            remote = list_remote_auth_files(base, key, timeout=float(args.timeout))
            log(f"[*] remote files: {len(remote)}")
            for f in remote:
                n = str(f.get("id") or f.get("name") or "").strip()
                em = str(f.get("email") or f.get("account") or "").strip().lower()
                if n:
                    remote_index[n] = f
                    remote_index[n.lower()] = f
                if em:
                    remote_index[em] = f
        except Exception as exc:  # noqa: BLE001
            log(f"[!] remote auth-files index failed (continue with inspection only): {exc}")
        targets = collect_inspection_targets(
            base_url=base,
            api_key=key,
            classes=insp_classes,
            remote_index=remote_index,
            timeout=max(float(args.timeout), 90.0),
            log=log,
        )
        if args.email:
            email_want = str(args.email).strip()
            targets = [
                t
                for t in targets
                if t.get("email") == email_want or t.get("name") == email_want
            ]
            log(f"[*] after --email filter targets={len(targets)}")
        return targets

    log(f"[*] listing remote auth-files from {base}")
    remote = list_remote_auth_files(base, key, timeout=float(args.timeout))
    log(f"[*] remote files: {len(remote)}")

    for f in remote:
        name = str(f.get("id") or f.get("name") or "").strip()
        if not name.endswith(".json"):
            continue
        email = str(f.get("email") or f.get("account") or _email_from_name(name)).strip()
        if args.email and email != args.email and name != args.email:
            continue
        local = load_local_auth(auth_dir, name)
        # cheap prefilter without download
        need, reason = needs_reactivation(
            remote_meta=f,
            local_payload=local,
            remote_payload=None,
            min_failed=int(args.min_failed),
            expired_only=bool(args.expired),
            disabled_only=bool(args.disabled),
            include_ok=bool(args.all),
            stale_hours=float(args.stale_hours),
        )
        if args.email:
            need = True
            reason = "forced_email"
        if not need:
            continue
        targets.append({"name": name, "email": email, "remote_meta": f, "reason": reason})
    return targets


def summarize_remote(remote: list[dict[str, Any]], auth_dir: Path, log: LogFn) -> None:
    now = _now()
    failed = sum(1 for f in remote if int(f.get("failed") or 0) > 0)
    no_lr = sum(1 for f in remote if not f.get("last_refresh"))
    disabled = sum(1 for f in remote if f.get("disabled"))
    local_exp = 0
    local_ok = 0
    local_miss = 0
    for f in remote:
        name = str(f.get("id") or f.get("name") or "")
        p = auth_dir / name
        if not p.is_file():
            local_miss += 1
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            local_miss += 1
            continue
        if is_expired_payload(d, now):
            local_exp += 1
        else:
            local_ok += 1
    log(
        f"[*] remote summary total={len(remote)} failed>0={failed} "
        f"no_last_refresh={no_lr} disabled={disabled} "
        f"local_expired={local_exp} local_ok={local_ok} local_missing={local_miss}"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Reactivate expired/dead CPA xai auth files")
    p.add_argument("--config", default="config.json", help="path to config.json")
    p.add_argument(
        "--accounts",
        default="accounts.json",
        help="ledger with email/password for protocol CreateSession remint",
    )
    p.add_argument("--auth-dir", default="", help="override cpa_auth_dir")
    p.add_argument("--dry-run", action="store_true", help="list targets only, no refresh/protocol/push")
    p.add_argument("--limit", type=int, default=0, help="max accounts to process (0=all)")
    p.add_argument("--workers", type=int, default=2, help="concurrent workers")
    p.add_argument("--timeout", type=float, default=45.0, help="HTTP timeout seconds")
    p.add_argument("--min-failed", type=int, default=1, help="remote failed threshold")
    p.add_argument(
        "--stale-hours", type=float, default=6.0, help="treat last_refresh older than this + failed as dead"
    )
    p.add_argument("--expired", action="store_true", help="only process expired access tokens")
    p.add_argument(
        "--disabled",
        action="store_true",
        help="only process disabled/停用 accounts (remote disabled=true or local payload disabled). "
        "NOT the same as 巡检需重登 — use --from-inspection reauth for that",
    )
    p.add_argument(
        "--from-inspection",
        nargs="?",
        const="reauth",
        default=None,
        metavar="CLASS",
        help="only accounts from grok-inspection plugin results. "
        "CLASS default=reauth (需重新登录). comma-separated e.g. reauth or reauth,permission_denied. "
        "Do NOT use --disabled for 巡检需重登",
    )
    p.add_argument("--all", action="store_true", help="process every remote/local file")
    p.add_argument("--email", default="", help="only this email or xai-*.json name")
    p.add_argument("--local-only", action="store_true", help="do not query remote; use local cpa_auths only")
    p.add_argument("--refresh-only", action="store_true", help="only try refresh_token; no protocol remint")
    p.add_argument(
        "--remint-only",
        action="store_true",
        help="skip refresh_token; protocol CreateSession+CF only",
    )
    p.add_argument(
        "--force-remint",
        action="store_true",
        help="always try protocol remint after refresh fail",
    )
    p.add_argument(
        "--no-browser",
        action="store_true",
        help="do not fall back to CF Turnstile (protocol remint needs CF token)",
    )
    p.add_argument(
        "--headed",
        action="store_true",
        help="force headed Chromium for Turnstile only (not full login UI)",
    )
    p.add_argument(
        "--headless",
        action="store_true",
        help="force headless Chromium for Turnstile only",
    )
    p.add_argument(
        "--browser-timeout",
        type=float,
        default=0.0,
        help="legacy flag; unused for protocol path (Turnstile uses turnstile_* config)",
    )
    p.add_argument("--no-push", action="store_true", help="write local only, do not push CPA")
    p.add_argument("--report", default="", help="optional JSON report path")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg_path = Path(args.config).expanduser()
    if not cfg_path.is_absolute():
        cfg_path = (ROOT / cfg_path).resolve()
    if not cfg_path.is_file():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 2

    cfg = _load_config(cfg_path)
    auth_dir = Path(args.auth_dir or cfg.get("cpa_auth_dir") or "cpa_auths").expanduser()
    if not auth_dir.is_absolute():
        auth_dir = (ROOT / auth_dir).resolve()
    accounts_path = Path(args.accounts).expanduser()
    if not accounts_path.is_absolute():
        accounts_path = (ROOT / accounts_path).resolve()

    accounts = load_accounts_map(accounts_path)
    _log(f"[*] config={cfg_path}")
    _log(f"[*] auth_dir={auth_dir} accounts={len(accounts)}")
    _log(
        f"[*] mode dry_run={args.dry_run} workers={args.workers} "
        f"min_failed={args.min_failed} expired={args.expired} disabled={args.disabled} "
        f"from_inspection={args.from_inspection!r} "
        f"refresh_only={args.refresh_only} remint_only={args.remint_only} "
        f"no_browser={args.no_browser} no_push={args.no_push}"
    )

    if not args.local_only:
        base = str(cfg.get("cpa_push_base_url") or "").rstrip("/")
        key = str(cfg.get("cpa_push_api_key") or "").strip()
        if base and key:
            try:
                remote = list_remote_auth_files(base, key, timeout=float(args.timeout))
                summarize_remote(remote, auth_dir, _log)
            except Exception as exc:  # noqa: BLE001
                _log(f"[!] remote summary failed: {exc}")

    targets = collect_targets(cfg=cfg, auth_dir=auth_dir, args=args, log=_log)
    # stable order: highest remote failed first, then name
    def _sort_key(t: dict[str, Any]) -> tuple:
        meta = t.get("remote_meta") or {}
        return (-int(meta.get("failed") or 0), str(t.get("name") or ""))

    targets.sort(key=_sort_key)
    if args.limit and args.limit > 0:
        targets = targets[: int(args.limit)]

    _log(f"[*] targets={len(targets)}")
    if not targets:
        _log("[*] nothing to do")
        return 0

    if args.dry_run:
        for t in targets[:50]:
            meta = t.get("remote_meta") or {}
            _log(
                f"  - {t['name']} reason={t.get('reason')} "
                f"failed={meta.get('failed')} last_refresh={meta.get('last_refresh')}"
            )
        if len(targets) > 50:
            _log(f"  ... and {len(targets) - 50} more")

    workers = max(1, int(args.workers or 1))
    results: list[dict[str, Any]] = []
    ok = fail = skip = refresh_n = protocol_n = push_ok = 0
    t0 = time.time()

    def _job(t: dict[str, Any], worker_id: int = 0) -> dict[str, Any]:
        return process_one(
            name=t["name"],
            email=t["email"],
            remote_meta=t.get("remote_meta"),
            cfg=cfg,
            auth_dir=auth_dir,
            accounts=accounts,
            args=args,
            log=_log,
            worker_id=int(worker_id or 0),
            seed_reason=str(t.get("reason") or "") or None,
        )

    if workers == 1 or args.dry_run:
        for i, t in enumerate(targets, 1):
            r = _job(t, worker_id=0)
            results.append(r)
            tag = "dry" if r.get("dry_run") else ("skip" if r.get("skipped") else ("ok" if r.get("ok") else "fail"))
            _log(
                f"[{i}/{len(targets)}] {tag} {t['name']} method={r.get('method')} "
                f"reason={r.get('reason')} err={r.get('error') or ''}"
            )
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {}
            for i, t in enumerate(targets):
                futs[ex.submit(_job, t, worker_id=i % workers)] = t
            done = 0
            for fut in as_completed(futs):
                done += 1
                t = futs[fut]
                try:
                    r = fut.result()
                except Exception as exc:  # noqa: BLE001
                    r = {"ok": False, "name": t["name"], "email": t["email"], "error": str(exc)}
                results.append(r)
                tag = "skip" if r.get("skipped") else ("ok" if r.get("ok") else "fail")
                _log(
                    f"[{done}/{len(targets)}] {tag} {t['name']} method={r.get('method')} "
                    f"push={r.get('cpa_push_ok')} err={r.get('error') or ''}"
                )

    for r in results:
        if r.get("skipped") or r.get("dry_run"):
            skip += 1
            continue
        if r.get("ok"):
            ok += 1
            if r.get("method") == "refresh":
                refresh_n += 1
            elif r.get("method") in {"protocol", "browser"}:
                # browser kept for old reports; new path is protocol
                protocol_n += 1
            if r.get("cpa_push_ok"):
                push_ok += 1
        else:
            fail += 1

    elapsed = time.time() - t0
    _log(
        f"[+] done ok={ok} fail={fail} skip/dry={skip} "
        f"refresh={refresh_n} protocol={protocol_n} push_ok={push_ok} "
        f"elapsed={elapsed:.1f}s"
    )

    if args.report:
        report_path = Path(args.report).expanduser()
        if not report_path.is_absolute():
            report_path = (ROOT / report_path).resolve()
        report_path.write_text(
            json.dumps(
                {
                    "ok": ok,
                    "fail": fail,
                    "skip": skip,
                    "refresh": refresh_n,
                    "protocol": protocol_n,
                    "browser": protocol_n,  # alias for older consumers
                    "push_ok": push_ok,
                    "elapsed_sec": elapsed,
                    "results": results,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        _log(f"[*] report → {report_path}")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
