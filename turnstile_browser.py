"""Minimal Turnstile token grabber for accounts.x.ai.

Only used for CF Turnstile — signup RPCs stay pure HTTP.
Backends:
  local — system Chrome via DrissionPage (auto_port, multi-open safe)
  roxy  — Roxy fingerprint browser (CDP attach)

Multi-worker batch (pages-per-window):
  Workers share browser *windows*. Each window keeps N tabs (default 3).
  worker_id → browser_id = worker // N, tab_index = worker % N.
  Turnstile is solved on that window's corresponding tab — no new window
  per account when turnstile_browser_reuse is true.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"

# Reuse production Roxy client (append, do NOT shadow this project's modules)
_REF_DIR = Path(__import__("os").environ.get("GROKX_BROWSER_BACKEND_DIR", "") or "")
if _REF_DIR.is_dir() and str(_REF_DIR) not in sys.path:
    sys.path.append(str(_REF_DIR))

# browser_id → seat {
#   backend, browser (root ChromiumPage), tabs: list[page], tab_locks: list[Lock],
#   meta, proxy, pages_per, lock (browser-level), browser_id
# }
_SEATS: dict[int, dict[str, Any]] = {}
_SEATS_LOCK = threading.Lock()
# browser_id → Lock: serialize first-time open so multi-tab workers share one window
_CREATE_LOCKS: dict[int, threading.Lock] = {}
_CREATE_LOCKS_GUARD = threading.Lock()


def _create_lock_for(browser_id: int) -> threading.Lock:
    with _CREATE_LOCKS_GUARD:
        lk = _CREATE_LOCKS.get(int(browser_id))
        if lk is None:
            lk = threading.Lock()
            _CREATE_LOCKS[int(browser_id)] = lk
        return lk


def _proxy_for_chromium(proxy: str | None) -> str:
    try:
        import proxyutil as px

        return px.proxy_for_chromium(proxy)
    except Exception:
        p = (proxy or "").strip()
        if not p:
            return ""
        try:
            from urllib.parse import urlparse

            u = urlparse(p if "://" in p else f"http://{p}")
            host = u.hostname or ""
            if not host:
                return ""
            port = u.port or (443 if (u.scheme or "http") == "https" else 80)
            scheme = u.scheme or "http"
            return f"{scheme}://{host}:{port}"
        except Exception:
            return p


def _proxy_identity(proxy: str | None) -> str:
    try:
        import proxyutil as px

        return px.proxy_identity(proxy) or (proxy or "")
    except Exception:
        return (proxy or "").strip()


def _pages_per_window(cfg: dict | None) -> int:
    cfg = cfg or {}
    for key in ("browser_pages_per_window", "turnstile_pages_per_browser", "pages_per_browser"):
        if key in cfg and cfg.get(key) is not None:
            try:
                return max(1, int(cfg.get(key) or 1))
            except (TypeError, ValueError):
                return 1
    return 3


def _map_worker(worker_id: int, pages_per: int) -> tuple[int, int]:
    pages_per = max(1, int(pages_per or 1))
    wid = max(0, int(worker_id or 0))
    return wid // pages_per, wid % pages_per


def _click_turnstile_checkbox(page: Any, log: Callable[[str], None]) -> str:
    """Auto-click Turnstile checkbox — same path as grok_register_ttk.getTurnstileToken.

    Flow:
      input[name=cf-turnstile-response]
        → parent.shadow_root → iframe
        → patch MouseEvent.screenX/Y
        → iframe body.shadow_root → input checkbox → click
      fallback: click visible turnstile nodes / host widget
    """
    # 1) shadow-DOM checkbox click (primary path from previous project)
    try:
        challenge_input = page.ele("@name=cf-turnstile-response")
    except Exception:
        challenge_input = None

    if challenge_input:
        try:
            wrapper = challenge_input.parent()
            iframe = None
            try:
                iframe = wrapper.shadow_root.ele("tag:iframe")
            except Exception:
                iframe = None
            # also try under our explicit host
            if iframe is None:
                try:
                    host = page.ele("#__proto_ts_host")
                    if host:
                        iframe = host.ele("tag:iframe") or (
                            host.shadow_root.ele("tag:iframe")
                            if getattr(host, "shadow_root", None)
                            else None
                        )
                except Exception:
                    pass
            if iframe:
                try:
                    iframe.run_js(
                        """
window.dtp = 1;
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
let sx = getRandomInt(800, 1200);
let sy = getRandomInt(400, 700);
Object.defineProperty(MouseEvent.prototype, 'screenX', { value: sx });
Object.defineProperty(MouseEvent.prototype, 'screenY', { value: sy });
"""
                    )
                except Exception:
                    pass
                try:
                    body_sr = iframe.ele("tag:body").shadow_root
                    btn = body_sr.ele("tag:input")
                    if btn:
                        btn.click()
                        return "shadow-input"
                except Exception:
                    pass
                # some CF builds put the clickable area on the iframe itself
                try:
                    iframe.click()
                    return "iframe"
                except Exception:
                    pass
        except Exception as exc:
            log(f"[turnstile] shadow click failed: {exc}")

    # 2) JS fallback: click host / turnstile nodes / iframes (previous project)
    try:
        hit = page.run_js(
            """
// prefer our explicit host widget (top-left)
const host = document.getElementById('__proto_ts_host');
if (host) {
  const iframe = host.querySelector('iframe');
  if (iframe && typeof iframe.click === 'function') {
    iframe.click();
    return 'host-iframe';
  }
  if (typeof host.click === 'function') {
    host.click();
    return 'host';
  }
}
const nodes = Array.from(
  document.querySelectorAll(
    'div,span,iframe,input[name="cf-turnstile-response"],.cf-turnstile,[data-sitekey]'
  )
).filter((n) => {
  const txt =
    (n.className || '') + ' ' +
    (n.id || '') + ' ' +
    (n.getAttribute?.('src') || '') + ' ' +
    (n.getAttribute?.('name') || '');
  return String(txt).toLowerCase().includes('turnstile')
    || n.id === '__proto_ts_host'
    || (n.getAttribute && n.getAttribute('name') === 'cf-turnstile-response');
});
if (nodes.length && typeof nodes[0].click === 'function') {
  nodes[0].click();
  return 'node:' + (nodes[0].tagName || '');
}
// last resort: any challenges.cloudflare iframe
const cf = document.querySelector('iframe[src*="challenges.cloudflare"]');
if (cf && typeof cf.click === 'function') {
  cf.click();
  return 'cf-iframe';
}
return '';
"""
        )
        if hit:
            return str(hit)
    except Exception as exc:
        log(f"[turnstile] js click failed: {exc}")
    return ""


def _ts_timing(cfg: dict | None) -> dict[str, float]:
    """Turnstile solve delays (seconds). Faster defaults; override via config.

    Keys (all optional in config.json):
      turnstile_page_wait_sec     — after signup page load (default 1.0, was 2.5)
      turnstile_api_poll_sec      — wait for window.turnstile (default 0.3, was 0.8)
      turnstile_paint_wait_sec    — after render before first click (default 0.5, was 1.2)
      turnstile_poll_interval_sec — token scan loop (default 0.35, was 1.0)
      turnstile_click_interval_sec— re-click checkbox (default 0.8, was 1.5)
      turnstile_rerender_wait_sec — after error re-render (default 0.5, was 1.0)
    """
    c = cfg or {}

    def _f(key: str, default: float, lo: float = 0.05, hi: float = 30.0) -> float:
        try:
            v = float(c.get(key, default) if c.get(key) is not None else default)
        except (TypeError, ValueError):
            v = default
        return max(lo, min(hi, v))

    return {
        "page_wait": _f("turnstile_page_wait_sec", 1.0, 0.2, 10.0),
        "api_poll": _f("turnstile_api_poll_sec", 0.3, 0.05, 3.0),
        "paint_wait": _f("turnstile_paint_wait_sec", 0.5, 0.1, 5.0),
        "poll_interval": _f("turnstile_poll_interval_sec", 0.35, 0.1, 3.0),
        "click_interval": _f("turnstile_click_interval_sec", 0.8, 0.2, 5.0),
        "rerender_wait": _f("turnstile_rerender_wait_sec", 0.5, 0.1, 5.0),
    }


def _render_and_poll(
    page: Any,
    *,
    sitekey: str,
    timeout: float,
    log: Callable[[str], None],
    cfg: dict | None = None,
) -> str:
    """Inject explicit Turnstile API, render widget, auto-click checkbox, poll token."""
    timing = _ts_timing(cfg)
    try:
        snap = page.run_js(
            "return {href:location.href,title:document.title,"
            "hasApi:typeof window.turnstile};"
        )
        log(f"[turnstile] page={snap}")
    except Exception as exc:
        log(f"[turnstile] page snap failed: {exc}")

    page.run_js(
        """
const already = document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]');
if (!already) {
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  document.head.appendChild(s);
}
return true;
"""
    )

    api_ready = False
    # ~same wall-clock budget as old 25×0.8s, but denser polls
    api_tries = max(8, int(20.0 / max(timing["api_poll"], 0.05)))
    for i in range(api_tries):
        st = page.run_js(
            "return {has: typeof window.turnstile, "
            "keys: window.turnstile ? Object.keys(window.turnstile) : []};"
        )
        if isinstance(st, dict) and st.get("has") == "object":
            log(f"[turnstile] api ready i={i} keys={st.get('keys')}")
            api_ready = True
            break
        time.sleep(timing["api_poll"])
    if not api_ready:
        log("[turnstile] turnstile API never loaded")
        return ""

    res = page.run_js(
        f"""
window.__ts_token = null;
window.__ts_err = null;
let el = document.getElementById('__proto_ts_host');
if (!el) {{
  el = document.createElement('div');
  el.id = '__proto_ts_host';
  el.style.cssText = 'position:fixed;left:10px;top:10px;z-index:2147483647;'
    + 'background:#fff;padding:10px;min-width:300px;min-height:65px;';
  (document.body || document.documentElement).appendChild(el);
}}
el.innerHTML = '';
try {{
  const id = turnstile.render(el, {{
    sitekey: {sitekey!r},
    callback: (t) => {{ window.__ts_token = t; }},
    'error-callback': (e) => {{ window.__ts_err = String(e || 'error'); }},
    'expired-callback': () => {{ window.__ts_token = null; }},
  }});
  window.__ts_widget_id = id;
  return {{ok: true, id}};
}} catch (e) {{
  return {{ok: false, err: String(e)}};
}}
"""
    )
    log(f"[turnstile] render={res}")

    # give widget a moment to paint checkbox before first click
    time.sleep(timing["paint_wait"])

    deadline = time.time() + max(15.0, timeout - 10)
    n = 0
    last_click_at = 0.0
    click_every = timing["click_interval"]
    poll_every = timing["poll_interval"]
    log(
        f"[turnstile] scan timing poll={poll_every:.2f}s "
        f"click={click_every:.2f}s paint={timing['paint_wait']:.2f}s"
    )
    while time.time() < deadline:
        n += 1
        info = page.run_js(
            """
let resp = '';
try {
  const byInput = String(
    (document.querySelector('input[name="cf-turnstile-response"]') || {}).value || ''
  ).trim();
  if (byInput) resp = byInput;
} catch (e) {}
try {
  if (!resp && window.turnstile && turnstile.getResponse) {
    resp = String(
      turnstile.getResponse(window.__ts_widget_id)
      || turnstile.getResponse()
      || ''
    );
  }
} catch (e) {}
try {
  const iframes = [...document.querySelectorAll('iframe')];
  window.__ts_iframes = iframes.length;
} catch (e) {}
return {
  token: window.__ts_token || resp || '',
  err: window.__ts_err || '',
  iframes: window.__ts_iframes || 0,
};
"""
        ) or {}
        # denser polls → log first 5, then every ~2s worth of iterations
        log_every = max(3, int(2.0 / max(poll_every, 0.05)))
        if n <= 5 or n % log_every == 0:
            preview = info
            if isinstance(info, dict) and info.get("token"):
                t = str(info["token"])
                preview = {**info, "token": t[:40] + "…" if len(t) > 40 else t}
            log(f"[turnstile] poll#{n} {preview}")
        if isinstance(info, dict):
            token = str(info.get("token") or "").strip()
            if len(token) >= 80:
                log(f"[turnstile] got token len={len(token)}")
                return token
            if info.get("err"):
                log(f"[turnstile] err={info.get('err')}")
                page.run_js(
                    f"""
window.__ts_err = null;
window.__ts_token = null;
const el = document.getElementById('__proto_ts_host');
if (el) el.innerHTML = '';
try {{
  window.__ts_widget_id = turnstile.render(
    document.getElementById('__proto_ts_host'),
    {{
      sitekey: {sitekey!r},
      callback: (t) => {{ window.__ts_token = t; }},
      'error-callback': (e) => {{ window.__ts_err = String(e || 'error'); }},
    }}
  );
}} catch (e) {{ window.__ts_err = String(e); }}
return true;
"""
                )
                time.sleep(timing["rerender_wait"])
                last_click_at = 0.0  # force re-click after re-render

        # auto-click checkbox until token appears
        now = time.time()
        if now - last_click_at >= click_every:
            hit = _click_turnstile_checkbox(page, log)
            last_click_at = now
            if hit and (n <= 5 or n % log_every == 0):
                log(f"[turnstile] auto-click → {hit}")

        time.sleep(poll_every)

    log("[turnstile] timeout waiting for token")
    return ""


def _apply_stealth(page: Any) -> None:
    try:
        page.run_cdp(
            "Page.addScriptToEvaluateOnNewDocument",
            source=(
                "Object.defineProperty(navigator,'webdriver',"
                "{get:()=>undefined});"
            ),
        )
    except Exception:
        pass


def _open_local_browser(
    *,
    proxy: str | None,
    headless: bool,
    log: Callable[[str], None],
    browser_id: int = 0,
    pages_per: int = 3,
):
    """Launch one local Chrome with `pages_per` tabs."""
    from DrissionPage import ChromiumOptions, ChromiumPage

    co = ChromiumOptions()
    # Critical for multi-open: each process gets its own debug port + profile
    try:
        co.auto_port()
    except Exception:
        try:
            co.set_argument("--remote-debugging-port=0")
        except Exception:
            pass
    if headless:
        try:
            co.headless(True)
        except Exception:
            co.set_argument("--headless=new")
    co.set_argument("--disable-blink-features=AutomationControlled")
    co.set_argument("--no-first-run")
    co.set_argument("--no-default-browser-check")
    co.set_argument("--disable-backgrounding-occluded-windows")
    co.set_argument("--disable-renderer-backgrounding")
    co.set_argument("--window-size=1100,900")
    # offset windows so multi-open is visible
    try:
        x = 40 + (int(browser_id) % 4) * 40
        y = 40 + (int(browser_id) % 4) * 40
        co.set_argument(f"--window-position={x},{y}")
    except Exception:
        pass

    chrome_proxy = _proxy_for_chromium(proxy)
    if chrome_proxy:
        try:
            co.set_proxy(chrome_proxy)
        except Exception:
            co.set_argument(f"--proxy-server={chrome_proxy}")
        log(
            f"[turnstile] local chrome b{browser_id} "
            f"tabs={pages_per} proxy={chrome_proxy}"
        )
    else:
        log(f"[turnstile] local chrome b{browser_id} tabs={pages_per} direct (no proxy)")

    root = ChromiumPage(co)
    _apply_stealth(root)
    tabs = _ensure_tab_count(root, pages_per, log=log, label=f"local-b{browser_id}")
    meta = {"kind": "local", "browser_id": browser_id, "pages_per": pages_per}
    return root, tabs, meta


def _open_roxy_browser(
    cfg: dict,
    *,
    proxy: str | None,
    log: Callable[[str], None],
    browser_id: int = 0,
    pages_per: int = 3,
):
    try:
        import browser_backend as bb
    except ImportError as exc:
        raise RuntimeError(
            f"browser_backend missing (need grok-register): {exc}"
        ) from exc

    # Roxy window name is keyed by browser_id (not worker_id) so N workers share it
    meta = bb.launch_roxy_browser(
        cfg,
        proxy_url=(proxy or "").strip(),
        worker_id=int(browser_id or 0),
        log=log,
    )
    # keep cfg on meta so release_roxy_meta can call API later
    if isinstance(meta, dict):
        meta["cfg"] = cfg
        meta["delete_on_stop"] = bool(cfg.get("roxy_delete_on_stop", False))
        meta["browser_id"] = int(browser_id)
        meta["pages_per"] = int(pages_per)
    http_addr = str(meta.get("http") or "").strip()
    if not http_addr:
        raise RuntimeError("Roxy open missing debug http address")

    from DrissionPage import ChromiumOptions, ChromiumPage

    opts = ChromiumOptions()
    try:
        opts.set_address(http_addr)
    except Exception:
        opts.set_argument(f"--remote-debugging-address={http_addr}")
    root = ChromiumPage(addr_or_opts=opts)
    log(
        f"[turnstile] attached Roxy b{browser_id} tabs={pages_per} "
        f"debug={http_addr} dirId={meta.get('dir_id')}"
    )
    tabs = _ensure_tab_count(root, pages_per, log=log, label=f"roxy-b{browser_id}")
    return root, tabs, meta


def _ensure_tab_count(
    root: Any,
    pages_per: int,
    *,
    log: Callable[[str], None],
    label: str = "",
) -> list[Any]:
    """Return exactly `pages_per` tab handles on this browser.

    Tab 0 is the root ChromiumPage; extra tabs via new_tab().
    """
    pages_per = max(1, int(pages_per or 1))
    tabs: list[Any] = [root]
    # Prefer existing page tabs if we re-attached
    try:
        existing = root.get_tabs(tab_type="page")
        if existing:
            # root may already be one of them — keep root as [0], append others
            for t in existing:
                if t is root:
                    continue
                # some Drission versions return same singleton — skip dups by tab_id
                try:
                    tid = getattr(t, "tab_id", None)
                    rid = getattr(root, "tab_id", None)
                    if tid and rid and tid == rid:
                        continue
                except Exception:
                    pass
                tabs.append(t)
                if len(tabs) >= pages_per:
                    break
    except Exception as exc:
        log(f"[turnstile] {label} list tabs: {exc}")

    while len(tabs) < pages_per:
        try:
            t = root.new_tab(url="about:blank", background=True)
            if t is None:
                raise RuntimeError("new_tab returned None")
            tabs.append(t)
            log(f"[turnstile] {label} opened tab {len(tabs) - 1}/{pages_per}")
        except Exception as exc:
            log(f"[turnstile] {label} new_tab failed: {exc}")
            # fall back: reuse root for remaining slots (serialized via locks)
            while len(tabs) < pages_per:
                tabs.append(root)
            break

    if len(tabs) > pages_per:
        tabs = tabs[:pages_per]
    log(f"[turnstile] {label} ready tabs={len(tabs)}")
    return tabs


def _tab_alive(tab: Any) -> bool:
    if tab is None:
        return False
    try:
        # light probe
        _ = getattr(tab, "tab_id", None)
        if hasattr(tab, "states"):
            try:
                return bool(getattr(tab.states, "is_alive", True))
            except Exception:
                pass
        tab.run_js("return 1")
        return True
    except Exception:
        return False


def _close_seat(seat: dict[str, Any], log: Callable[[str], None]) -> None:
    browser = seat.get("browser")
    page = seat.get("page")  # legacy single-page field
    meta = seat.get("meta") or {}
    backend = seat.get("backend") or ""
    root = browser if browser is not None else page
    if root is not None and backend != "roxy":
        try:
            root.quit()
        except Exception:
            pass
    if backend == "roxy" and meta:
        try:
            import browser_backend as bb

            # pass seat cfg if present so API token/base survive release
            bb.release_roxy_meta(
                meta,
                delete=bool((meta or {}).get("delete_on_stop")),
                log=log,
                cfg=(meta.get("cfg") if isinstance(meta, dict) else None),
            )
        except Exception as exc:
            log(f"[turnstile] roxy release: {exc}")


def _roxy_refresh_each_account(cfg: dict) -> bool:
    """Whether to close/clear/reopen Roxy between accounts.

    Default False — multi-tab reuse keeps the window for the whole batch.
    Set roxy_refresh_each_account=true to restore old per-account restart.
    """
    if "roxy_refresh_each_account" in cfg:
        v = cfg.get("roxy_refresh_each_account")
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("1", "true", "yes", "on", "y")
    return False


def _ensure_seat(
    *,
    browser_id: int,
    pages_per: int,
    backend: str,
    proxy: str | None,
    headless: bool,
    cfg: dict,
    log: Callable[[str], None],
    reuse: bool,
) -> dict[str, Any]:
    """Return (and optionally create) a multi-tab browser seat.

    Local Chrome / Roxy:
      reuse keeps the process + tabs across accounts (default).
      Roxy only restarts when roxy_refresh_each_account=true.
      Proxy is browser-level; all tabs share it. If a later request's proxy
      differs, we keep the existing window (no mid-batch recreate) unless
      pages_per==1 and the old single-tab recreate-on-proxy-change path applies.
    """
    pages_per = max(1, int(pages_per or 1))
    create_lk = _create_lock_for(browser_id)

    # Serialize create/recreate per browser_id so workers sharing a window
    # don't open N Roxy/Chrome processes for the same seat.
    with create_lk:
        with _SEATS_LOCK:
            seat = _SEATS.get(int(browser_id))
            if seat is not None and reuse:
                refresh_roxy = backend == "roxy" and _roxy_refresh_each_account(cfg)
                proxy_changed = (
                    _proxy_identity(seat.get("proxy")) != _proxy_identity(proxy)
                )
                need_recreate = False
                if refresh_roxy:
                    log(
                        f"[turnstile] b{browser_id} Roxy refresh seat "
                        f"(roxy_refresh_each_account=true)"
                    )
                    need_recreate = True
                elif proxy_changed and pages_per == 1 and backend != "roxy":
                    log(
                        f"[turnstile] b{browser_id} proxy changed, recreate browser seat"
                    )
                    need_recreate = True
                elif proxy_changed and pages_per > 1:
                    log(
                        f"[turnstile] b{browser_id} proxy differs from seat "
                        f"(keep shared window; tabs={pages_per})"
                    )
                if need_recreate:
                    try:
                        _close_seat(seat, log)
                    except Exception:
                        pass
                    _SEATS.pop(int(browser_id), None)
                    seat = None
                else:
                    return seat

        # create while holding create_lk (slow path)
        if backend == "roxy":
            root, tabs, meta = _open_roxy_browser(
                cfg,
                proxy=proxy,
                log=log,
                browser_id=browser_id,
                pages_per=pages_per,
            )
        else:
            root, tabs, meta = _open_local_browser(
                proxy=proxy,
                headless=headless,
                log=log,
                browser_id=browser_id,
                pages_per=pages_per,
            )
        seat = {
            "backend": backend,
            "browser": root,
            "page": root,  # legacy alias
            "tabs": list(tabs),
            "tab_locks": [threading.Lock() for _ in range(len(tabs))],
            "meta": meta,
            "proxy": proxy or "",
            "browser_id": int(browser_id),
            "pages_per": pages_per,
            "lock": threading.Lock(),  # browser-level (tab create / recreate)
        }
        while len(seat["tab_locks"]) < pages_per:
            seat["tab_locks"].append(threading.Lock())
        while len(seat["tabs"]) < pages_per:
            seat["tabs"].append(root)

        if reuse:
            with _SEATS_LOCK:
                old = _SEATS.get(int(browser_id))
                if old is not None and old is not seat:
                    try:
                        _close_seat(old, log)
                    except Exception:
                        pass
                _SEATS[int(browser_id)] = seat
        return seat


def _repair_tab(
    seat: dict[str, Any],
    tab_index: int,
    log: Callable[[str], None],
) -> Any:
    """Recreate a single dead tab inside an existing browser seat."""
    tabs: list[Any] = seat.get("tabs") or []
    root = seat.get("browser") or seat.get("page")
    if root is None:
        return None
    pages_per = int(seat.get("pages_per") or len(tabs) or 1)
    tab_index = max(0, min(int(tab_index), pages_per - 1))

    with seat.get("lock") or threading.Lock():
        # re-check after lock
        tabs = seat.get("tabs") or []
        while len(tabs) <= tab_index:
            tabs.append(root)
        cur = tabs[tab_index]
        if _tab_alive(cur):
            return cur
        log(f"[turnstile] b{seat.get('browser_id')} tab{tab_index} dead, recreating")
        try:
            if cur is not None and cur is not root:
                try:
                    cur.close()
                except Exception:
                    pass
            if tab_index == 0:
                # root died — try get_tab(0) or fail (caller will drop seat)
                try:
                    new_tab = root.get_tab(1) if hasattr(root, "get_tab") else root
                except Exception:
                    new_tab = root
                if not _tab_alive(new_tab):
                    return None
                tabs[0] = new_tab
                seat["browser"] = new_tab
                seat["page"] = new_tab
                seat["tabs"] = tabs
                return new_tab
            new_tab = root.new_tab(url="about:blank", background=True)
            tabs[tab_index] = new_tab
            seat["tabs"] = tabs
            return new_tab
        except Exception as exc:
            log(f"[turnstile] tab recreate failed: {exc}")
            return None


def release_worker_browser(
    worker_id: int, log: Callable[[str], None] | None = None
) -> None:
    """Release the browser seat that hosts this worker's tab.

    With multi-tab mapping this closes the whole shared window (all tabs).
    Prefer release_all_browsers at batch end.
    """
    log = log or (lambda m: print(m, flush=True))
    # pages_per unknown here — close browser_id assuming default map with any pages_per
    # Safe path: close seat whose browser_id matches map for common pages_per values
    with _SEATS_LOCK:
        # try reverse-lookup: any seat; if only one mapping style used, worker//N
        candidates = set()
        for pages_per in (1, 2, 3, 4, 5, 6, 8, 10):
            candidates.add(int(worker_id) // pages_per)
        to_close = []
        for bid in candidates:
            seat = _SEATS.get(bid)
            if seat is not None:
                # only close if this worker actually maps onto that seat under its pages_per
                pp = int(seat.get("pages_per") or 1)
                if int(worker_id) // pp == bid:
                    to_close.append(bid)
        seats = []
        for bid in to_close:
            s = _SEATS.pop(bid, None)
            if s is not None:
                seats.append((bid, s))
    for bid, seat in seats:
        _close_seat(seat, log)
        log(f"[turnstile] closed browser seat b{bid} (via worker {worker_id})")


def release_browser(
    browser_id: int, log: Callable[[str], None] | None = None
) -> None:
    log = log or (lambda m: print(m, flush=True))
    with _SEATS_LOCK:
        seat = _SEATS.pop(int(browser_id), None)
    if seat:
        _close_seat(seat, log)


def release_all_browsers(log: Callable[[str], None] | None = None) -> int:
    """Close every browser seat. Call at end of batch."""
    log = log or (lambda m: print(m, flush=True))
    with _SEATS_LOCK:
        items = list(_SEATS.items())
        _SEATS.clear()
    for bid, seat in items:
        try:
            ntabs = len(seat.get("tabs") or [])
            _close_seat(seat, log)
            log(f"[turnstile] closed browser seat b{bid} (tabs={ntabs})")
        except Exception as exc:
            log(f"[turnstile] close seat b{bid} failed: {exc}")
    return len(items)


def solve_turnstile_browser(
    *,
    proxy: str | None = None,
    timeout: float = 90,
    headless: bool = False,
    log: Callable[[str], None] | None = None,
    sitekey: str = TURNSTILE_SITEKEY,
    backend: str = "local",
    config: dict | None = None,
    worker_id: int = 0,
) -> str:
    """Return a fresh Turnstile token, or "" on failure.

    Multi-tab: worker_id maps to (browser_id, tab_index) via
    browser_pages_per_window (default 3). Concurrent workers that share a
    window solve on different tabs of the same process / Roxy profile.
    """
    log = log or (lambda m: print(m, flush=True))
    cfg = config or {}
    backend = (backend or str(cfg.get("browser_backend") or "local")).strip().lower()
    if backend in ("fingerprint", "roxybrowser"):
        backend = "roxy"
    reuse = bool(cfg.get("turnstile_browser_reuse", True))
    pages_per = _pages_per_window(cfg)
    browser_id, tab_index = _map_worker(worker_id, pages_per)

    try:
        from DrissionPage import ChromiumOptions, ChromiumPage  # noqa: F401
    except ImportError as exc:
        log(f"[turnstile] DrissionPage missing: {exc}")
        return ""

    seat = None
    owned_ephemeral = False
    try:
        if backend == "roxy":
            log(
                f"[turnstile] backend=Roxy worker={worker_id} "
                f"→ b{browser_id}/tab{tab_index} "
                f"pages_per={pages_per} reuse={reuse}"
            )
            if proxy:
                log(
                    f"[turnstile] Roxy seat proxy: "
                    f"{_proxy_for_chromium(proxy) or proxy}"
                )
        else:
            log(
                f"[turnstile] backend=local Chrome worker={worker_id} "
                f"→ b{browser_id}/tab{tab_index} "
                f"pages_per={pages_per} reuse={reuse}"
            )

        seat = _ensure_seat(
            browser_id=browser_id,
            pages_per=pages_per,
            backend=backend,
            proxy=proxy,
            headless=headless,
            cfg=cfg,
            log=log,
            reuse=reuse,
        )
        owned_ephemeral = not reuse
        tabs = seat.get("tabs") or [seat.get("browser") or seat.get("page")]
        if tab_index >= len(tabs):
            tab_index = tab_index % max(1, len(tabs))
        locks = seat.get("tab_locks") or [seat.get("lock") or threading.Lock()]
        if tab_index >= len(locks):
            # pad
            while len(locks) <= tab_index:
                locks.append(threading.Lock())
            seat["tab_locks"] = locks
        tab_lock = locks[tab_index]

        with tab_lock:
            tab = tabs[tab_index]
            if not _tab_alive(tab):
                tab = _repair_tab(seat, tab_index, log)
                if tab is None:
                    raise RuntimeError(
                        f"browser b{browser_id} tab{tab_index} dead and unrepaired"
                    )
                tabs = seat.get("tabs") or tabs
                tab = tabs[tab_index]

            log(
                f"[turnstile] open {SIGNUP_URL} "
                f"(w{worker_id} b{browser_id}/tab{tab_index})"
            )
            tab.get(SIGNUP_URL)
            page_wait = _ts_timing(cfg)["page_wait"]
            time.sleep(page_wait)
            return _render_and_poll(
                tab, sitekey=sitekey, timeout=timeout, log=log, cfg=cfg
            )
    except Exception as exc:  # noqa: BLE001
        log(f"[turnstile] browser error w{worker_id} b{browser_id}/tab{tab_index}: {exc}")
        # broken seat — drop so next account recreates the whole window
        if reuse:
            release_browser(browser_id, log=log)
        return ""
    finally:
        if owned_ephemeral and seat is not None:
            try:
                _close_seat(seat, log)
            except Exception:
                pass
