"""Cloudflare temp-mail helpers (mail.oo-ooo.fun style)."""

from __future__ import annotations

import re
import secrets
import string
import time
from typing import Callable

import requests

DEFAULT_BASE = "https://mail.oo-ooo.fun"


def _headers(api_key: str = "", content_type: bool = False) -> dict:
    h: dict[str, str] = {}
    if content_type:
        h["Content-Type"] = "application/json"
    if api_key:
        h["x-custom-auth"] = api_key
    return h


def create_address(
    api_base: str,
    api_key: str,
    domain: str = "oo-ooo.fun",
    name: str | None = None,
) -> tuple[str, str]:
    """POST /api/new_address → (address, jwt)."""
    api_base = api_base.rstrip("/")
    name = name or "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    payload = {"name": name, "domain": domain}
    r = requests.post(
        f"{api_base}/api/new_address",
        json=payload,
        headers=_headers(api_key, content_type=True),
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected new_address response: {data!r}")
    address = data.get("address") or ""
    jwt = data.get("jwt") or data.get("token") or ""
    if isinstance(data.get("data"), dict):
        address = address or data["data"].get("address") or ""
        jwt = jwt or data["data"].get("jwt") or data["data"].get("token") or ""
    if not address or not jwt:
        raise RuntimeError(f"new_address missing address/jwt: {data}")
    return str(address), str(jwt)


def list_mails(api_base: str, jwt: str, api_key: str = "") -> list[dict]:
    api_base = api_base.rstrip("/")
    h = _headers(api_key)
    h["Authorization"] = f"Bearer {jwt}"
    r = requests.get(
        f"{api_base}/api/mails",
        headers=h,
        params={"limit": 20, "offset": 0},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "messages", "mails"):
            if isinstance(data.get(key), list):
                return data[key]
        if isinstance(data.get("data"), list):
            return data["data"]
        if isinstance(data.get("data"), dict) and isinstance(
            data["data"].get("messages"), list
        ):
            return data["data"]["messages"]
    return []


def extract_code(text: str, subject: str = "") -> str | None:
    blob = f"{subject}\n{text}"
    m = re.search(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", subject, re.I)
    if m:
        return m.group(1)
    m = re.search(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", blob, re.I)
    if m:
        return m.group(1)
    for pat in (
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})",
    ):
        m = re.search(pat, blob, re.I)
        if m:
            return m.group(1)
    return None


def wait_code(
    api_base: str,
    jwt: str,
    api_key: str = "",
    *,
    timeout: float = 120,
    poll_interval: float = 3,
    log: Callable[[str], None] | None = None,
) -> str:
    deadline = time.time() + timeout
    seen: set[str] = set()
    while time.time() < deadline:
        try:
            mails = list_mails(api_base, jwt, api_key)
        except Exception as exc:  # noqa: BLE001
            if log:
                log(f"[mail] list failed: {exc}")
            time.sleep(poll_interval)
            continue
        if log:
            log(f"[mail] {len(mails)} message(s)")
        for msg in mails:
            mid = str(msg.get("id") or msg.get("msgid") or "")
            parts = []
            subject = str(msg.get("subject") or "")
            for field in ("text", "raw", "content", "intro", "body", "snippet", "html"):
                val = msg.get(field)
                if isinstance(val, str) and val.strip():
                    parts.append(re.sub(r"<[^>]+>", " ", val))
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str):
                            parts.append(re.sub(r"<[^>]+>", " ", item))
            text = "\n".join(parts)
            code = extract_code(text, subject)
            if code:
                if log:
                    log(f"[mail] code={code} subject={subject[:80]}")
                return code
            if mid:
                seen.add(mid)
        time.sleep(poll_interval)
    raise TimeoutError(f"no verification code within {timeout}s")
