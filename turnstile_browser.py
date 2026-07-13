"""Minimal Turnstile token grabber for accounts.x.ai.

Only used for CF Turnstile — signup RPCs stay pure HTTP.
Backends:
  local — system Chrome via DrissionPage (auto_port, multi-open safe)
  roxy  — Roxy fingerprint browser (CDP attach), one window per worker

Multi-worker batch:
  Each worker_id keeps its own browser seat (local process or Roxy window).
  Tokens are solved on that seat without serializing across workers.
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

# worker_id → seat {backend, page, meta, proxy, lock, worker_id}
_SEATS: dict[int, dict[str, Any]] = {}
_SEATS_LOCK = threading.Lock()


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


def _render_and_poll(
    page: Any, *, sitekey: str, timeout: float, log: Callable[[str], None]
) -> str:
    """Inject explicit Turnstile API, render widget, auto-click checkbox, poll token."""
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
    for i in range(25):
        st = page.run_js(
            "return {has: typeof window.turnstile, "
            "keys: window.turnstile ? Object.keys(window.turnstile) : []};"
        )
        if isinstance(st, dict) and st.get("has") == "object":
            log(f"[turnstile] api ready i={i} keys={st.get('keys')}")
            api_ready = True
            break
        time.sleep(0.8)
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
    time.sleep(1.2)

    deadline = time.time() + max(15.0, timeout - 10)
    n = 0
    last_click_at = 0.0
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
        if n <= 3 or n % 5 == 0:
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
                time.sleep(1.0)
                last_click_at = 0.0  # force re-click after re-render

        # auto-click checkbox every ~1.5s until token appears (reference: 1s loop)
        now = time.time()
        if now - last_click_at >= 1.5:
            hit = _click_turnstile_checkbox(page, log)
            last_click_at = now
            if hit and (n <= 3 or n % 5 == 0):
                log(f"[turnstile] auto-click → {hit}")

        time.sleep(1.0)

    log("[turnstile] timeout waiting for token")
    return ""


def _open_local_page(
    *,
    proxy: str | None,
    headless: bool,
    log: Callable[[str], None],
    worker_id: int = 0,
):
    """Launch a dedicated local Chrome. auto_port so multi-worker does not clash."""
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
        x = 40 + (int(worker_id) % 4) * 40
        y = 40 + (int(worker_id) % 4) * 40
        co.set_argument(f"--window-position={x},{y}")
    except Exception:
        pass

    chrome_proxy = _proxy_for_chromium(proxy)
    if chrome_proxy:
        try:
            co.set_proxy(chrome_proxy)
        except Exception:
            co.set_argument(f"--proxy-server={chrome_proxy}")
        log(f"[turnstile] local chrome w{worker_id} proxy={chrome_proxy}")
    else:
        log(f"[turnstile] local chrome w{worker_id} direct (no proxy)")

    page = ChromiumPage(co)
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
    return page, {"kind": "local", "worker_id": worker_id}


def _open_roxy_page(
    cfg: dict,
    *,
    proxy: str | None,
    log: Callable[[str], None],
    worker_id: int = 0,
):
    try:
        import browser_backend as bb
    except ImportError as exc:
        raise RuntimeError(
            f"browser_backend missing (need grok-register): {exc}"
        ) from exc

    meta = bb.launch_roxy_browser(
        cfg,
        proxy_url=(proxy or "").strip(),
        worker_id=int(worker_id or 0),
        log=log,
    )
    http_addr = str(meta.get("http") or "").strip()
    if not http_addr:
        raise RuntimeError("Roxy open missing debug http address")

    from DrissionPage import ChromiumOptions, ChromiumPage

    opts = ChromiumOptions()
    try:
        opts.set_address(http_addr)
    except Exception:
        opts.set_argument(f"--remote-debugging-address={http_addr}")
    page = ChromiumPage(addr_or_opts=opts)
    log(
        f"[turnstile] attached Roxy w{worker_id} debug={http_addr} "
        f"dirId={meta.get('dir_id')}"
    )
    return page, meta


def _close_seat(seat: dict[str, Any], log: Callable[[str], None]) -> None:
    page = seat.get("page")
    meta = seat.get("meta") or {}
    backend = seat.get("backend") or ""
    if page is not None and backend != "roxy":
        try:
            page.quit()
        except Exception:
            pass
    if backend == "roxy" and meta:
        try:
            import browser_backend as bb

            bb.release_roxy_meta(meta, delete=False, log=log)
        except Exception as exc:
            log(f"[turnstile] roxy release: {exc}")


def _proxy_identity(proxy: str | None) -> str:
    try:
        import proxyutil as px

        return px.proxy_identity(proxy) or (proxy or "")
    except Exception:
        return (proxy or "").strip()


def _ensure_seat(
    *,
    worker_id: int,
    backend: str,
    proxy: str | None,
    headless: bool,
    cfg: dict,
    log: Callable[[str], None],
    reuse: bool,
) -> dict[str, Any]:
    """Return (and optionally create) a browser seat for this worker.

    Roxy (same as reference BrowserSession.restart):
      every account re-enters launch_roxy_browser:
        close process → clear data → update proxy → random_env → open
      reuse only keeps the window *profile* (dirId by stable name), not dirty cookies.

    Local Chrome:
      reuse keeps the process when proxy is unchanged (Turnstile-only, no login).
    """
    with _SEATS_LOCK:
        seat = _SEATS.get(int(worker_id))
        if seat is not None and reuse:
            # Roxy: always refresh profile between accounts (clear + fingerprint + proxy)
            # so each Turnstile run matches the previous project's restart path.
            if backend == "roxy":
                log(
                    f"[turnstile] w{worker_id} Roxy refresh seat "
                    f"(clear data + random fingerprint + proxy)"
                )
                try:
                    _close_seat(seat, log)
                except Exception:
                    pass
                _SEATS.pop(int(worker_id), None)
                seat = None
            elif _proxy_identity(seat.get("proxy")) != _proxy_identity(proxy):
                log(
                    f"[turnstile] w{worker_id} proxy changed, recreate browser seat"
                )
                try:
                    _close_seat(seat, log)
                except Exception:
                    pass
                _SEATS.pop(int(worker_id), None)
                seat = None
            else:
                return seat

    # create outside global lock (opening browser is slow)
    if backend == "roxy":
        page, meta = _open_roxy_page(
            cfg, proxy=proxy, log=log, worker_id=worker_id
        )
    else:
        page, meta = _open_local_page(
            proxy=proxy, headless=headless, log=log, worker_id=worker_id
        )
    seat = {
        "backend": backend,
        "page": page,
        "meta": meta,
        "proxy": proxy or "",
        "worker_id": int(worker_id),
        "lock": threading.Lock(),
    }
    if reuse:
        with _SEATS_LOCK:
            # another thread may have created one — keep ours, drop orphan
            old = _SEATS.get(int(worker_id))
            if old is not None and old is not seat:
                try:
                    _close_seat(old, log)
                except Exception:
                    pass
            _SEATS[int(worker_id)] = seat
    return seat


def release_worker_browser(
    worker_id: int, log: Callable[[str], None] | None = None
) -> None:
    log = log or (lambda m: print(m, flush=True))
    with _SEATS_LOCK:
        seat = _SEATS.pop(int(worker_id), None)
    if seat:
        _close_seat(seat, log)


def release_all_browsers(log: Callable[[str], None] | None = None) -> int:
    """Close every worker seat. Call at end of batch."""
    log = log or (lambda m: print(m, flush=True))
    with _SEATS_LOCK:
        items = list(_SEATS.items())
        _SEATS.clear()
    for wid, seat in items:
        try:
            _close_seat(seat, log)
            log(f"[turnstile] closed browser seat w{wid}")
        except Exception as exc:
            log(f"[turnstile] close seat w{wid} failed: {exc}")
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

    Multi-open: each worker_id has its own seat (local process or Roxy window).
    Roxy always re-runs clear data + random fingerprint + proxy before open
    (same as previous project BrowserSession.restart), even when reuse=True.
    Local Chrome may keep the process when proxy is unchanged.
    """
    log = log or (lambda m: print(m, flush=True))
    cfg = config or {}
    backend = (backend or str(cfg.get("browser_backend") or "local")).strip().lower()
    if backend in ("fingerprint", "roxybrowser"):
        backend = "roxy"
    reuse = bool(cfg.get("turnstile_browser_reuse", True))

    try:
        from DrissionPage import ChromiumOptions, ChromiumPage  # noqa: F401
    except ImportError as exc:
        log(f"[turnstile] DrissionPage missing: {exc}")
        return ""

    seat = None
    owned_ephemeral = False
    try:
        if backend == "roxy":
            log(f"[turnstile] backend=Roxy worker={worker_id} reuse={reuse}")
            if proxy:
                log(
                    f"[turnstile] Roxy 将绑定代理: "
                    f"{_proxy_for_chromium(proxy) or proxy}"
                )
        else:
            log(f"[turnstile] backend=local Chrome worker={worker_id} reuse={reuse}")

        seat = _ensure_seat(
            worker_id=worker_id,
            backend=backend,
            proxy=proxy,
            headless=headless,
            cfg=cfg,
            log=log,
            reuse=reuse,
        )
        owned_ephemeral = not reuse
        page = seat["page"]
        lock = seat.get("lock") or threading.Lock()

        with lock:
            log(f"[turnstile] open {SIGNUP_URL} (w{worker_id})")
            page.get(SIGNUP_URL)
            time.sleep(2.5)
            return _render_and_poll(
                page, sitekey=sitekey, timeout=timeout, log=log
            )
    except Exception as exc:  # noqa: BLE001
        log(f"[turnstile] browser error w{worker_id}: {exc}")
        # broken seat — drop so next account recreates
        if reuse:
            release_worker_browser(worker_id, log=log)
        return ""
    finally:
        if owned_ephemeral and seat is not None:
            try:
                _close_seat(seat, log)
            except Exception:
                pass
