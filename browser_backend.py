"""Roxy Browser local OpenAPI client for GrokX Turnstile seats.

Expected by turnstile_browser.py:
  launch_roxy_browser(cfg, proxy_url=..., worker_id=..., log=...) -> meta
  release_roxy_meta(meta, delete=False, log=...)

Local API (after Roxy login + API Key):
  host default http://127.0.0.1:50000
  header: token: <API Key>
  docs: https://roxybrowser.com/docs/api-documentation/api-endpoint.html
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse


LogFn = Callable[[str], None]


def _log(log: LogFn | None, msg: str) -> None:
    (log or (lambda m: print(m, flush=True)))(msg)


def _cfg_str(cfg: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        v = cfg.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return default


def _cfg_bool(cfg: dict, key: str, default: bool = False) -> bool:
    v = cfg.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n", ""):
        return False
    return default


def _cfg_int(cfg: dict, key: str, default: int = 0) -> int:
    try:
        return int(cfg.get(key, default) or default)
    except Exception:
        return default


def _api_base(cfg: dict) -> str:
    base = _cfg_str(cfg, "roxy_api_base", default="http://127.0.0.1:50000")
    return base.rstrip("/")


def _token(cfg: dict) -> str:
    return _cfg_str(cfg, "roxy_api_token", "roxy_token", "api_token")


def _timeout(cfg: dict) -> float:
    try:
        return float(cfg.get("roxy_timeout_sec") or 60)
    except Exception:
        return 60.0


def _request(
    cfg: dict,
    method: str,
    path: str,
    *,
    body: dict | list | None = None,
    query: dict | None = None,
    log: LogFn | None = None,
) -> dict[str, Any]:
    token = _token(cfg)
    if not token:
        raise RuntimeError(
            "roxy_api_token empty — open Roxy → API → API配置 → copy API Key into config.json"
        )
    url = _api_base(cfg) + path
    if query:
        qs = urllib.parse.urlencode(
            {k: v for k, v in query.items() if v is not None and v != ""},
            doseq=True,
        )
        if qs:
            url = f"{url}?{qs}"
    data = None
    headers = {
        "token": token,
        "User-Agent": "GrokX/1.0",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=_timeout(cfg)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            code_http = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Roxy HTTP {exc.code} {method} {path}: {raw[:400]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Roxy API unreachable at {_api_base(cfg)} ({exc}). "
            "Login Roxy first; API host default is 127.0.0.1:50000 (API → API配置)."
        ) from exc
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        raise RuntimeError(
            f"Roxy non-JSON response HTTP {code_http}: {raw[:300]}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Roxy unexpected payload type: {type(payload)}")
    code = payload.get("code", 0)
    if code not in (0, "0", None):
        msg = payload.get("msg") or payload.get("message") or payload
        raise RuntimeError(f"Roxy API error code={code} {method} {path}: {msg}")
    return payload


def health(cfg: dict, log: LogFn | None = None) -> dict[str, Any]:
    return _request(cfg, "GET", "/health", log=log)


def list_workspaces(cfg: dict, log: LogFn | None = None) -> list[dict[str, Any]]:
    payload = _request(
        cfg,
        "GET",
        "/browser/workspace",
        query={"page_index": 1, "page_size": 50},
        log=log,
    )
    data = payload.get("data") or {}
    if isinstance(data, list):
        return data
    rows = data.get("rows") if isinstance(data, dict) else None
    return list(rows or [])


def resolve_workspace_id(cfg: dict, log: LogFn | None = None) -> int:
    raw = _cfg_str(cfg, "roxy_workspace_id", "workspace_id")
    if raw:
        return int(raw)
    rows = list_workspaces(cfg, log=log)
    if not rows:
        raise RuntimeError("Roxy workspace list empty — login / create a team first")
    wid = rows[0].get("id") or rows[0].get("workspaceId")
    if wid is None:
        raise RuntimeError(f"Roxy workspace row missing id: {rows[0]!r}")
    _log(log, f"[roxy] auto workspaceId={wid} name={rows[0].get('workspaceName')}")
    return int(wid)


def resolve_project_id(cfg: dict, workspace_id: int, log: LogFn | None = None) -> int | None:
    raw = _cfg_str(cfg, "roxy_project_id", "project_id")
    if raw:
        return int(raw)
    # Prefer project_details from workspace list if present
    for row in list_workspaces(cfg, log=log):
        if int(row.get("id") or row.get("workspaceId") or -1) != int(workspace_id):
            continue
        details = row.get("project_details") or row.get("projectDetails") or []
        if details:
            pid = details[0].get("projectId") or details[0].get("id")
            if pid is not None:
                return int(pid)
    return None


def _parse_proxy_url(proxy_url: str) -> dict[str, str]:
    p = (proxy_url or "").strip()
    if not p:
        return {}
    if "://" not in p:
        p = "http://" + p
    u = urlparse(p)
    host = u.hostname or ""
    if not host:
        return {}
    port = u.port or (443 if (u.scheme or "http") == "https" else 80)
    scheme = (u.scheme or "http").upper()
    if scheme not in ("HTTP", "HTTPS", "SOCKS5", "SOCKS4"):
        # chromium-style http proxy for GrokX local clash
        scheme = "HTTP"
    out = {
        "protocol": scheme if scheme != "SOCKS4" else "SOCKS5",
        "host": host,
        "port": str(port),
    }
    if u.username:
        out["proxyUserName"] = urllib.parse.unquote(u.username)
    if u.password:
        out["proxyPassword"] = urllib.parse.unquote(u.password)
    return out


def _proxy_info(cfg: dict, proxy_url: str) -> dict[str, Any]:
    if _cfg_bool(cfg, "roxy_use_proxy_manager", False):
        # Let Roxy manager pick; still allow empty custom when no proxy
        return {"proxyCategory": "noproxy"} if not (proxy_url or "").strip() else {
            "proxyMethod": "custom",
            "proxyCategory": "HTTP",
            **_parse_proxy_url(proxy_url),
        }
    parsed = _parse_proxy_url(proxy_url)
    if not parsed:
        return {
            "proxyMethod": "custom",
            "proxyCategory": "noproxy",
        }
    return {
        "proxyMethod": "custom",
        "proxyCategory": parsed.get("protocol") or "HTTP",
        "ipType": "IPV4",
        "protocol": parsed.get("protocol") or "HTTP",
        "host": parsed["host"],
        "port": parsed["port"],
        **(
            {"proxyUserName": parsed["proxyUserName"]}
            if "proxyUserName" in parsed
            else {}
        ),
        **(
            {"proxyPassword": parsed["proxyPassword"]}
            if "proxyPassword" in parsed
            else {}
        ),
    }


def _window_name(cfg: dict, worker_id: int) -> str:
    prefix = _cfg_str(cfg, "roxy_window_name_prefix", default="grokx-ts")
    return f"{prefix}-w{int(worker_id)}"


def find_profile_by_name(
    cfg: dict,
    *,
    workspace_id: int,
    window_name: str,
    log: LogFn | None = None,
) -> dict[str, Any] | None:
    payload = _request(
        cfg,
        "GET",
        "/browser/list_v3",
        query={
            "workspaceId": workspace_id,
            "windowName": window_name,
            "page_index": 1,
            "page_size": 20,
        },
        log=log,
    )
    data = payload.get("data") or {}
    rows = data.get("rows") if isinstance(data, dict) else data
    for row in rows or []:
        if str(row.get("windowName") or "") == window_name:
            return row
        # soft match
        if window_name and window_name in str(row.get("windowName") or ""):
            return row
    return None


def create_profile(
    cfg: dict,
    *,
    workspace_id: int,
    window_name: str,
    proxy_url: str,
    log: LogFn | None = None,
) -> str:
    body: dict[str, Any] = {
        "workspaceId": workspace_id,
        "windowName": window_name,
        "os": _cfg_str(cfg, "roxy_os", default="Windows") or "Windows",
        "osVersion": _cfg_str(cfg, "roxy_os_version", default="11") or "11",
        "coreType": _cfg_str(cfg, "roxy_core_type", default="Chrome") or "Chrome",
        "proxyInfo": _proxy_info(cfg, proxy_url),
        "defaultOpenUrl": [],
        "openWorkbench": 0,
    }
    core = _cfg_str(cfg, "roxy_core_version", "coreVersion")
    if core:
        body["coreVersion"] = core
    project_id = resolve_project_id(cfg, workspace_id, log=log)
    if project_id is not None:
        body["projectId"] = project_id
    # fingerInfo minimal: let Roxy randomize on create/open when requested
    if _cfg_bool(cfg, "roxy_random_fingerprint", True):
        body["fingerInfo"] = {
            "isLanguageBaseIp": True,
            "isDisplayLanguageBaseIp": True,
            "isTimeZone": True,
            "isPositionBaseIp": True,
        }
    payload = _request(cfg, "POST", "/browser/create", body=body, log=log)
    data = payload.get("data") or {}
    dir_id = (
        data.get("dirId")
        if isinstance(data, dict)
        else None
    ) or (payload.get("dirId") if isinstance(payload, dict) else None)
    if not dir_id and isinstance(data, dict):
        # some versions nest
        dir_id = data.get("id") or data.get("dir_id")
    if not dir_id:
        raise RuntimeError(f"Roxy create missing dirId: {payload!r}")
    return str(dir_id)


def ensure_profile(
    cfg: dict,
    *,
    workspace_id: int,
    window_name: str,
    proxy_url: str,
    log: LogFn | None = None,
) -> str:
    reuse = _cfg_bool(cfg, "roxy_reuse_window", True)
    if reuse:
        row = find_profile_by_name(
            cfg, workspace_id=workspace_id, window_name=window_name, log=log
        )
        if row and row.get("dirId"):
            dir_id = str(row["dirId"])
            _log(log, f"[roxy] reuse profile name={window_name} dirId={dir_id}")
            # refresh proxy binding on reuse
            try:
                _request(
                    cfg,
                    "POST",
                    "/browser/mdf",
                    body={
                        "workspaceId": workspace_id,
                        "dirId": dir_id,
                        "proxyInfo": _proxy_info(cfg, proxy_url),
                    },
                    log=log,
                )
            except Exception as exc:
                _log(log, f"[roxy] mdf proxy warn: {exc}")
            return dir_id
    dir_id = create_profile(
        cfg,
        workspace_id=workspace_id,
        window_name=window_name,
        proxy_url=proxy_url,
        log=log,
    )
    _log(log, f"[roxy] created profile name={window_name} dirId={dir_id}")
    return dir_id


def close_browser(cfg: dict, dir_id: str, log: LogFn | None = None) -> None:
    if not dir_id:
        return
    try:
        _request(cfg, "POST", "/browser/close", body={"dirId": dir_id}, log=log)
    except Exception as exc:
        _log(log, f"[roxy] close {dir_id}: {exc}")


def clear_local_cache(cfg: dict, dir_id: str, log: LogFn | None = None) -> None:
    if not dir_id:
        return
    try:
        _request(
            cfg,
            "POST",
            "/browser/clear_local_cache",
            body={"dirIds": [dir_id], "type": "all"},
            log=log,
        )
    except Exception as exc:
        _log(log, f"[roxy] clear_local_cache {dir_id}: {exc}")


def random_env(
    cfg: dict, *, workspace_id: int, dir_id: str, log: LogFn | None = None
) -> None:
    try:
        _request(
            cfg,
            "POST",
            "/browser/random_env",
            body={"workspaceId": workspace_id, "dirId": dir_id},
            log=log,
        )
    except Exception as exc:
        _log(log, f"[roxy] random_env {dir_id}: {exc}")


def open_browser(
    cfg: dict,
    *,
    workspace_id: int,
    dir_id: str,
    log: LogFn | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "workspaceId": workspace_id,
        "dirId": dir_id,
        "forceOpen": True,
        "headless": _cfg_bool(cfg, "roxy_headless", False),
        "args": ["--remote-allow-origins=*"],
    }
    payload = _request(cfg, "POST", "/browser/open", body=body, log=log)
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    if not isinstance(data, dict):
        data = {}
    # normalize http address for DrissionPage set_address
    http = str(data.get("http") or data.get("httpUrl") or data.get("debugHttp") or "").strip()
    ws = str(data.get("ws") or data.get("webSocketDebuggerUrl") or "").strip()
    if not http and ws:
        # ws://127.0.0.1:PORT/devtools/browser/...
        try:
            u = urlparse(ws)
            if u.hostname and u.port:
                http = f"{u.hostname}:{u.port}"
        except Exception:
            pass
    if http.startswith("http://"):
        http = http[len("http://") :]
    if http.startswith("https://"):
        http = http[len("https://") :]
    if not http:
        raise RuntimeError(f"Roxy open missing http/ws endpoint: {payload!r}")
    return {
        "dir_id": dir_id,
        "workspace_id": workspace_id,
        "http": http,
        "ws": ws,
        "pid": data.get("pid"),
        "raw": data,
        "kind": "roxy",
    }


def delete_profile(
    cfg: dict, *, workspace_id: int, dir_id: str, log: LogFn | None = None
) -> None:
    if not dir_id:
        return
    try:
        _request(
            cfg,
            "POST",
            "/browser/delete",
            body={
                "workspaceId": workspace_id,
                "dirIds": [dir_id],
                "isSoftDelete": True,
            },
            log=log,
        )
    except Exception as exc:
        _log(log, f"[roxy] delete {dir_id}: {exc}")


def launch_roxy_browser(
    cfg: dict,
    *,
    proxy_url: str = "",
    worker_id: int = 0,
    log: LogFn | None = None,
) -> dict[str, Any]:
    """Open (or refresh) one Roxy window for this worker and return CDP meta.

    Refresh path matches previous BrowserSession.restart semantics when reuse:
      close process → clear local data → update proxy → random fingerprint → open
    """
    cfg = cfg or {}
    log = log or (lambda m: print(m, flush=True))
    # connectivity probe
    try:
        health(cfg, log=log)
    except Exception as exc:
        # health may 401 without token path differences; re-raise clear message
        raise RuntimeError(str(exc)) from exc

    workspace_id = resolve_workspace_id(cfg, log=log)
    window_name = _window_name(cfg, worker_id)
    dir_id = ensure_profile(
        cfg,
        workspace_id=workspace_id,
        window_name=window_name,
        proxy_url=proxy_url or "",
        log=log,
    )

    # always stop previous process for this profile before re-open
    close_browser(cfg, dir_id, log=log)
    time.sleep(0.3)

    if _cfg_bool(cfg, "roxy_clear_data_on_reuse", True):
        clear_local_cache(cfg, dir_id, log=log)

    # re-bind proxy every launch (even if ensure_profile already mdf'd)
    try:
        _request(
            cfg,
            "POST",
            "/browser/mdf",
            body={
                "workspaceId": workspace_id,
                "dirId": dir_id,
                "proxyInfo": _proxy_info(cfg, proxy_url or ""),
            },
            log=log,
        )
    except Exception as exc:
        _log(log, f"[roxy] mdf before open: {exc}")

    if _cfg_bool(cfg, "roxy_random_fingerprint", True):
        random_env(cfg, workspace_id=workspace_id, dir_id=dir_id, log=log)

    meta = open_browser(cfg, workspace_id=workspace_id, dir_id=dir_id, log=log)
    meta["window_name"] = window_name
    meta["proxy"] = (proxy_url or "").strip()
    meta["worker_id"] = int(worker_id)
    meta["cfg_api_base"] = _api_base(cfg)
    _log(
        log,
        f"[roxy] open ok w{worker_id} dirId={dir_id} http={meta.get('http')} "
        f"proxy={_parse_proxy_url(proxy_url).get('host') or 'direct'}",
    )
    return meta


def release_roxy_meta(
    meta: dict[str, Any] | None,
    *,
    delete: bool = False,
    log: LogFn | None = None,
    cfg: dict | None = None,
) -> None:
    """Close (and optionally delete) a Roxy window described by launch meta."""
    if not meta:
        return
    log = log or (lambda m: print(m, flush=True))
    # reconstruct minimal cfg for API calls
    api_cfg = dict(cfg or {})
    if not api_cfg.get("roxy_api_base") and meta.get("cfg_api_base"):
        api_cfg["roxy_api_base"] = meta["cfg_api_base"]
    # token must still come from caller's config if cfg omitted — try common global
    if not _token(api_cfg):
        # best-effort: cannot call API without token
        _log(log, "[roxy] release skipped (no token in cfg)")
        return
    dir_id = str(meta.get("dir_id") or meta.get("dirId") or "").strip()
    workspace_id = meta.get("workspace_id") or meta.get("workspaceId")
    close_browser(api_cfg, dir_id, log=log)
    if delete and dir_id and workspace_id is not None:
        delete_profile(
            api_cfg, workspace_id=int(workspace_id), dir_id=dir_id, log=log
        )
    elif delete and dir_id and _cfg_bool(api_cfg, "roxy_delete_on_stop", False):
        # workspace unknown — skip hard delete
        _log(log, f"[roxy] delete requested but workspace_id missing for {dir_id}")
