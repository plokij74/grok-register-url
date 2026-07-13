"""Proxy pool / blacklist — aligned with grok-register/grok_register_ttk.py.

Priority when loading pool:
  1) config.proxies list
  2) Roxy IP proxy manager (browser_backend=roxy && roxy_use_proxy_manager)
  3) proxies_file (e.g. proxies.txt)
  4) single config.proxy (fallback when pool empty)

use_proxy=false → empty effective proxy (direct).
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
LogFn = Callable[[str], None]

_worker_proxy_tls = threading.local()
_proxy_bl_lock = threading.Lock()
_proxy_bl_cache: dict[str, Any] | None = None
_cfg_ref: dict[str, Any] | None = None

# Chain bridge maps: original residential URL ↔ local http://127.0.0.1:port
# (711 etc. only reachable via local Clash/V2)
_chain_lock = threading.Lock()
_chain_forward: dict[str, str] = {}  # original_norm -> bridge_url
_chain_reverse: dict[str, str] = {}  # bridge_url -> original_norm
_DEFAULT_CHAIN_KEYWORDS = (
    "711proxy",
    "rotgb",
    "kookeey",
    "gate.kookeey",
    "iproyal",
    "proxyrack",
)


def bind_config(cfg: dict[str, Any]) -> None:
    """Bind active config for pool/blacklist helpers."""
    global _cfg_ref, _proxy_bl_cache
    _cfg_ref = cfg
    _proxy_bl_cache = None  # reload blacklist path if config changed


def _cfg() -> dict[str, Any]:
    return _cfg_ref or {}


def set_worker_proxy(proxy: str | None) -> None:
    p = (proxy or "").strip()
    _worker_proxy_tls.proxy = p or None


def get_worker_proxy() -> str | None:
    return getattr(_worker_proxy_tls, "proxy", None)


def _is_loopback_host(host: str | None) -> bool:
    h = (host or "").strip().lower()
    return h in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def needs_local_chain(
    proxy: str | None, cfg: dict[str, Any] | None = None
) -> bool:
    """Whether this proxy must be dialed through local Clash/V2 first."""
    config = cfg if cfg is not None else _cfg()
    p = (proxy or "").strip()
    if not p:
        return False
    try:
        u = urlparse(p if "://" in p else f"socks5://{p}")
    except Exception:
        return False
    if _is_loopback_host(u.hostname):
        return False  # already local

    mode = str(config.get("proxy_via_local") or "auto").strip().lower()
    if mode in ("0", "false", "off", "no", "n"):
        return False
    if mode in ("1", "true", "on", "yes", "y", "all"):
        return True

    # auto: only known providers that block direct dial
    host = (u.hostname or "").lower()
    raw_kw = config.get("proxy_chain_host_keywords")
    if isinstance(raw_kw, str):
        keywords = [k.strip().lower() for k in raw_kw.split(",") if k.strip()]
    elif isinstance(raw_kw, (list, tuple)):
        keywords = [str(k).strip().lower() for k in raw_kw if str(k).strip()]
    else:
        keywords = list(_DEFAULT_CHAIN_KEYWORDS)
    return any(k in host for k in keywords if k)


def local_chain_upstream(cfg: dict[str, Any] | None = None) -> str:
    """Local hop for chain (default config.proxy if loopback)."""
    config = cfg if cfg is not None else _cfg()
    explicit = str(config.get("proxy_chain_local") or "").strip()
    if explicit:
        return normalize_proxy_url(explicit) or explicit
    fallback = normalize_proxy_url(config.get("proxy") or "") or ""
    if fallback:
        try:
            u = urlparse(fallback)
            if _is_loopback_host(u.hostname):
                return fallback
        except Exception:
            pass
    return "http://127.0.0.1:7890"


def apply_local_chain(
    proxy: str | None,
    cfg: dict[str, Any] | None = None,
    *,
    log: LogFn | None = None,
) -> str:
    """If proxy needs local hop, start/reuse HTTP bridge and return its URL.

    Clients (curl_cffi / Roxy) then use http://127.0.0.1:<port> with no auth;
    bridge does: local Clash → residential SOCKS → target.
    """
    log = log or (lambda m: print(m, flush=True))
    config = cfg if cfg is not None else _cfg()
    raw = (proxy or "").strip()
    if not raw:
        return ""
    norm = normalize_proxy_url(raw) or raw
    if not needs_local_chain(norm, config):
        return norm

    with _chain_lock:
        cached = _chain_forward.get(norm)
        if cached:
            return cached

    local = local_chain_upstream(config)
    try:
        from proxy_chain_bridge import ensure_bridge

        bridge = ensure_bridge(norm, local, log=log)
    except Exception as exc:
        log(f"[!] 代理链式桥启动失败 ({proxy_log_label(norm)} via {proxy_log_label(local)}): {exc}")
        return norm  # fall back to direct (likely still fails)

    with _chain_lock:
        _chain_forward[norm] = bridge
        _chain_reverse[bridge] = norm
        # also map identity of original for reverse lookups by host:port later
    log(
        f"[*] 链式代理: {proxy_log_label(norm)} → {bridge} "
        f"(via {proxy_log_label(local)})"
    )
    return bridge


def original_proxy_url(proxy: str | None) -> str:
    """Map bridge URL back to original residential URL when applicable."""
    p = (proxy or "").strip()
    if not p:
        return ""
    with _chain_lock:
        return _chain_reverse.get(p) or p


def stop_proxy_chains() -> None:
    """Stop all local chain bridges (batch cleanup)."""
    try:
        from proxy_chain_bridge import stop_all_bridges

        stop_all_bridges()
    except Exception:
        pass
    with _chain_lock:
        _chain_forward.clear()
        _chain_reverse.clear()


def normalize_proxy_url(raw: Any) -> str:
    """Normalize proxy URL.

    Supports:
      socks5h://user:pass@host:port  (preferred — remote DNS via proxy)
      socks5://user:pass@host:port   (upgraded to socks5h for curl_cffi)
      http://host:port
      host:port
      user:pass@host:port
      host:port:user:pass   (711-style)

    Important: curl_cffi + local DNS (plain socks5://) often fails TLS to
    accounts.x.ai on residential SOCKS (curl 35 OPENSSL_internal). socks5h
    forces hostname resolution through the proxy and works.
    Chromium still gets socks5:// via proxy_for_chromium().
    """
    p = (str(raw) if raw is not None else "").strip()
    if not p or p.startswith("#"):
        return ""
    if "://" in p:
        # socks5 → socks5h so curl does remote DNS (fixes TLS to CF sites)
        try:
            from urllib.parse import urlparse, urlunparse

            u = urlparse(p)
            scheme = (u.scheme or "").lower()
            if scheme in ("socks5", "socks"):
                return urlunparse(("socks5h", u.netloc, u.path, u.params, u.query, u.fragment))
            if scheme == "socks4a":
                return p
            return p
        except Exception:
            return p
    parts = p.split(":")
    if len(parts) >= 4 and parts[1].isdigit():
        host, port = parts[0], parts[1]
        user = parts[2]
        pwd = ":".join(parts[3:])
        return f"socks5h://{user}:{pwd}@{host}:{port}"
    if "@" in p:
        return f"socks5h://{p}"
    return f"socks5h://{p}"


def proxy_log_label(proxy: str | None) -> str:
    p = (proxy or "").strip()
    if not p:
        return "(none)"
    # Annotate chain bridges with their residential origin for logs.
    orig = ""
    with _chain_lock:
        orig = _chain_reverse.get(p) or ""
    try:
        u = urlparse(p if "://" in p else f"http://{p}")
        host = u.hostname or "?"
        port = u.port or ""
        auth = "user:***@" if u.username else ""
        label = f"{u.scheme or 'http'}://{auth}{host}{(':' + str(port)) if port else ''}"
        if orig:
            try:
                ou = urlparse(orig if "://" in orig else f"socks5://{orig}")
                oh = ou.hostname or "?"
                op = ou.port or ""
                label = f"{label}<-{oh}{(':' + str(op)) if op else ''}"
            except Exception:
                label = f"{label}<-chain"
        return label
    except Exception:
        return "(proxy)"


def proxy_for_chromium(proxy: str | None) -> str:
    """Chromium --proxy-server cannot embed user:pass."""
    p = (proxy or "").strip()
    if not p:
        return ""
    u = urlparse(p if "://" in p else f"http://{p}")
    host = u.hostname or ""
    if not host:
        return ""
    scheme = (u.scheme or "http").lower()
    if scheme in ("socks5h", "socks"):
        scheme = "socks5"
    elif scheme == "socks4a":
        scheme = "socks4"
    port = u.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


def _parse_proxy_list(raw_list: Any) -> list[str]:
    """Keep duplicates: same gateway written N times = N worker seats."""
    out: list[str] = []
    for item in raw_list or []:
        p = normalize_proxy_url(item)
        if p:
            out.append(p)
    return out


def load_proxy_pool(cfg: dict[str, Any] | None = None, *, log: LogFn | None = None) -> list[str]:
    """Load proxy pool (fallback to local single proxy only when empty)."""
    config = cfg if cfg is not None else _cfg()
    log = log or (lambda m: print(m, flush=True))

    if not config.get("use_proxy", True):
        return []

    # 1) explicit list
    pool = _parse_proxy_list(config.get("proxies") or [])
    if pool:
        return pool

    # 2) Roxy IP proxy manager
    backend = str(config.get("browser_backend") or "local").strip().lower()
    use_mgr = bool(config.get("roxy_use_proxy_manager", True))
    if backend in ("roxy", "fingerprint", "roxybrowser") and use_mgr:
        try:
            import sys

            ref = Path(__import__("os").environ.get("GROKX_BROWSER_BACKEND_DIR", "") or "")
            if ref.is_dir() and str(ref) not in sys.path:
                sys.path.append(str(ref))
            import browser_backend as bb

            only_checked = bool(config.get("roxy_proxy_only_checked", False))
            mgr_pool = bb.load_roxy_proxy_pool(
                config, only_checked=only_checked, log=lambda m: None
            )
            mgr_pool = _parse_proxy_list(mgr_pool)
            if mgr_pool:
                return mgr_pool
        except Exception as exc:
            log(f"[!] 读取 Roxy 代理管理失败，将回退本地代理: {exc}")

    # 3) local proxies file
    proxies_file = str(config.get("proxies_file") or "").strip()
    if proxies_file:
        path = Path(proxies_file)
        if not path.is_absolute():
            path = ROOT / path
        if path.is_file():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
                file_pool = _parse_proxy_list(lines)
                if file_pool:
                    return file_pool
            except Exception as exc:
                log(f"[!] 读取代理文件失败 {path}: {exc}")

    # 4) fallback single
    single = normalize_proxy_url(config.get("proxy", ""))
    if single:
        log(f"[*] 代理池为空，回退本地代理: {proxy_log_label(single)}")
        return [single]
    return []


def _proxy_blacklist_path(cfg: dict[str, Any] | None = None) -> str:
    config = cfg if cfg is not None else _cfg()
    raw = str(config.get("proxy_blacklist_file") or "proxy_blacklist.json").strip()
    if os.path.isabs(raw):
        return raw
    return str(ROOT / raw)


def _proxy_identity(proxy: str | None) -> str:
    # Prefer original residential URL when proxy is a local chain bridge.
    p0 = original_proxy_url(proxy) if proxy else ""
    p = normalize_proxy_url(p0 or proxy) or (p0 or proxy or "").strip()
    if not p:
        return ""
    try:
        u = urlparse(p if "://" in p else f"socks5://{p}")
        host = (u.hostname or "").lower()
        if not host:
            return p
        port = u.port or (443 if (u.scheme or "").lower() == "https" else 80)
        return f"{host}:{int(port)}"
    except Exception:
        return p


def _is_loopback_proxy(proxy: str | None) -> bool:
    # Bridge URLs are loopback but represent a remote residential exit —
    # never treat them as "local fallback" for blacklist skip.
    with _chain_lock:
        if (proxy or "").strip() in _chain_reverse:
            return False
    p0 = original_proxy_url(proxy) if proxy else ""
    if p0 and p0 != (proxy or "").strip():
        # identity of the residential side
        key = _proxy_identity(p0)
    else:
        key = _proxy_identity(proxy)
    host = key.split(":")[0] if key else ""
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def _load_proxy_blacklist_unlocked(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    global _proxy_bl_cache
    if _proxy_bl_cache is not None:
        return _proxy_bl_cache
    path = _proxy_blacklist_path(cfg)
    data: dict[str, Any] = {"proxies": {}}
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                proxies = loaded.get("proxies")
                if isinstance(proxies, dict):
                    data["proxies"] = proxies
                else:
                    data["proxies"] = {
                        k: v for k, v in loaded.items() if isinstance(v, dict)
                    }
        except Exception:
            data = {"proxies": {}}
    _proxy_bl_cache = data
    return _proxy_bl_cache


def _save_proxy_blacklist_unlocked(cfg: dict[str, Any] | None = None) -> None:
    path = _proxy_blacklist_path(cfg)
    data = _proxy_bl_cache or {"proxies": {}}
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"[!] 保存代理黑名单失败: {exc}")


def _purge_expired_blacklist_unlocked(
    now: float | None = None, cfg: dict[str, Any] | None = None
) -> dict[str, Any]:
    now = float(now if now is not None else time.time())
    data = _load_proxy_blacklist_unlocked(cfg)
    proxies = data.setdefault("proxies", {})
    changed = False
    for key in list(proxies.keys()):
        row = proxies.get(key) or {}
        until = float(row.get("until") or 0)
        if until and until <= now:
            row["until"] = 0
            row["fails"] = 0
            proxies[key] = row
            changed = True
        if not float(row.get("until") or 0) and not int(row.get("fails") or 0):
            proxies.pop(key, None)
            changed = True
    if changed:
        _save_proxy_blacklist_unlocked(cfg)
    return data


def is_proxy_blacklisted(
    proxy: str | None, now: float | None = None, cfg: dict[str, Any] | None = None
) -> bool:
    key = _proxy_identity(proxy)
    if not key or _is_loopback_proxy(proxy):
        return False
    now = float(now if now is not None else time.time())
    with _proxy_bl_lock:
        data = _purge_expired_blacklist_unlocked(now, cfg)
        row = (data.get("proxies") or {}).get(key) or {}
        until = float(row.get("until") or 0)
        return until > now


def available_proxy_pool(
    pool: list[str] | None = None,
    cfg: dict[str, Any] | None = None,
    *,
    log: LogFn | None = None,
) -> list[str]:
    """Alive proxies; if all banned → fallback local proxy / original pool."""
    config = cfg if cfg is not None else _cfg()
    log = log or (lambda m: print(m, flush=True))
    if not config.get("use_proxy", True):
        return []
    pool = list(pool if pool is not None else load_proxy_pool(config, log=log))
    if not pool:
        single = normalize_proxy_url(config.get("proxy", ""))
        return [single] if single else []
    alive = [p for p in pool if not is_proxy_blacklisted(p, cfg=config)]
    if alive:
        return alive
    local = normalize_proxy_url(config.get("proxy", ""))
    if local and not is_proxy_blacklisted(local, cfg=config):
        log(f"[!] 代理池均在黑名单，回退本地代理: {proxy_log_label(local)}")
        return [local]
    log("[!] 代理池均在黑名单且无本地回退，临时放行全部代理")
    return pool


def _filter_excluded(pool: list[str], exclude: set[str] | None) -> list[str]:
    if not exclude:
        return list(pool)
    out: list[str] = []
    for p in pool:
        key = _proxy_identity(p)
        if key and key in exclude:
            continue
        if p in exclude:
            continue
        out.append(p)
    return out


def pick_random_proxy(
    pool: list[str] | None = None,
    cfg: dict[str, Any] | None = None,
    *,
    log: LogFn | None = None,
    exclude: set[str] | None = None,
) -> str:
    config = cfg if cfg is not None else _cfg()
    pool = available_proxy_pool(pool, config, log=log)
    pool = _filter_excluded(pool, exclude)
    if pool:
        return random.choice(pool)
    if exclude:
        return ""  # all candidates used/banned this round
    return normalize_proxy_url(config.get("proxy", "")) if config.get("use_proxy", True) else ""


def pick_proxy_for_worker(
    worker_id: int,
    pool: list[str] | None = None,
    cfg: dict[str, Any] | None = None,
    *,
    log: LogFn | None = None,
    exclude: set[str] | None = None,
) -> str:
    config = cfg if cfg is not None else _cfg()
    mode = str(config.get("proxy_pick_mode") or "random").strip().lower()
    pool = available_proxy_pool(pool, config, log=log)
    pool = _filter_excluded(pool, exclude)
    if not pool:
        return ""
    if mode == "sticky":
        return pool[int(worker_id) % len(pool)]
    return random.choice(pool)


def proxy_identity(proxy: str | None) -> str:
    """Public wrapper for host:port identity."""
    return _proxy_identity(proxy)


def report_proxy_success(proxy: str | None, cfg: dict[str, Any] | None = None) -> None:
    config = cfg if cfg is not None else _cfg()
    key = _proxy_identity(proxy)
    if not key or _is_loopback_proxy(proxy):
        return
    with _proxy_bl_lock:
        data = _load_proxy_blacklist_unlocked(config)
        row = (data.get("proxies") or {}).get(key)
        if not row:
            return
        if int(row.get("fails") or 0) == 0:
            return
        if float(row.get("until") or 0) > time.time():
            return
        row["fails"] = 0
        data.setdefault("proxies", {})[key] = row
        _save_proxy_blacklist_unlocked(config)


def report_proxy_failure(
    proxy: str | None,
    error: str = "",
    *,
    log: LogFn | None = None,
    cfg: dict[str, Any] | None = None,
) -> bool:
    """Count failure; ban after threshold. Returns True if newly banned."""
    config = cfg if cfg is not None else _cfg()
    key = _proxy_identity(proxy)
    if not key or _is_loopback_proxy(proxy):
        return False
    try:
        threshold = max(1, int(config.get("proxy_fail_threshold", 3) or 3))
    except (TypeError, ValueError):
        threshold = 3
    try:
        hours = max(1, float(config.get("proxy_blacklist_hours", 24) or 24))
    except (TypeError, ValueError):
        hours = 24.0
    now = time.time()
    newly_banned = False
    with _proxy_bl_lock:
        data = _purge_expired_blacklist_unlocked(now, config)
        proxies = data.setdefault("proxies", {})
        row = dict(proxies.get(key) or {})
        if float(row.get("until") or 0) > now:
            row["last_error"] = str(error or "")[:300]
            row["last_fail_at"] = int(now)
            row["label"] = proxy_log_label(proxy)
            proxies[key] = row
            _save_proxy_blacklist_unlocked(config)
            return False
        fails = int(row.get("fails") or 0) + 1
        row["fails"] = fails
        row["last_error"] = str(error or "")[:300]
        row["last_fail_at"] = int(now)
        row["label"] = proxy_log_label(proxy)
        if fails >= threshold:
            row["until"] = int(now + hours * 3600)
            row["banned_at"] = int(now)
            newly_banned = True
        proxies[key] = row
        _save_proxy_blacklist_unlocked(config)
    if log:
        label = proxy_log_label(proxy)
        if newly_banned:
            log(f"[!] 代理错误过多（{fails}/{threshold}），拉黑 {hours:g} 小时: {label}")
        else:
            log(f"[!] 代理失败计数 {fails}/{threshold}: {label}")
    return newly_banned


def is_retryable_proxy_error(exc: BaseException | str | None) -> bool:
    msg = str(exc or "").lower()
    if not msg:
        return False
    keys = (
        "connection to proxy closed",
        "cannot complete socks5",
        "socks5",
        "proxy closed",
        "proxy connect",
        "proxy connection",
        "tunnel connection failed",
        "proxyerror",
        "proxy error",
        "err_proxy",
        "407 proxy",
        "failed to connect to proxy",
        "proxy handshake",
        "connection refused",
        "timed out",
        "timeout",
        "network is unreachable",
        "could not resolve",
        "name or service not known",
        "proxy/network error",
        "auth warm proxy",
        "auth createemail",
        "curl: (5)",
        "curl: (6)",
        "curl: (7)",
        "curl: (28)",
        "curl: (35)",
        "curl: (56)",
        "curl: (97)",
        "failed to perform",
        "recv failure",
        "send failure",
        "operation timed out",
        "max retries exceeded",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "ssl",
        "handshake",
    )
    return any(k in msg for k in keys)


def resolve_mint_proxy(
    cfg: dict[str, Any],
    worker_proxy: str | None = None,
    *,
    log: LogFn | None = None,
) -> str | None:
    """mint_proxy > worker proxy > config.proxy; honour use_proxy.

    Applies local chain bridge when the residential hop needs it.
    """
    raw: str | None
    if not cfg.get("use_proxy", True):
        # mint can still use explicit mint_proxy even if register is direct
        mp = str(cfg.get("mint_proxy") or "").strip()
        raw = normalize_proxy_url(mp) or None
    else:
        mp = str(cfg.get("mint_proxy") or "").strip()
        if mp:
            raw = normalize_proxy_url(mp) or None
        elif worker_proxy:
            raw = normalize_proxy_url(worker_proxy) or None
        else:
            wp = get_worker_proxy()
            if wp:
                raw = normalize_proxy_url(wp) or None
            else:
                raw = normalize_proxy_url(cfg.get("proxy") or "") or None
    if not raw:
        return None
    return apply_local_chain(raw, cfg, log=log) or raw


def effective_register_proxy(
    cfg: dict[str, Any],
    *,
    worker_id: int = 0,
    pool: list[str] | None = None,
    log: LogFn | None = None,
    exclude: set[str] | None = None,
) -> str:
    """Pick proxy for one register attempt (empty = direct)."""
    if not cfg.get("use_proxy", True):
        return ""
    return (
        pick_proxy_for_worker(
            worker_id, pool=pool, cfg=cfg, log=log, exclude=exclude
        )
        or ""
    )
