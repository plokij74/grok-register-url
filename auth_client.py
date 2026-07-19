"""Pure-HTTP xAI AuthManagement client (gRPC-Web over curl_cffi)."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import unquote

from curl_cffi import requests as cf_requests

from proto_codec import (
    build_create_email_validation_code,
    build_create_session_request,
    build_create_user_and_session,
    build_set_tos_accepted_version,
    build_verify_email_validation_code,
    grpc_web_frame,
    parse_fields,
    parse_grpc_web,
)

ACCOUNTS_BASE = "https://accounts.x.ai"
AUTH_SERVICE = "auth_mgmt.AuthManagement"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
# Next.js server action used by the browser for final create (wraps turnstile).
CREATE_USER_SERVER_ACTION = "7f50061dd2f5b389a530e4a048d5fdf0c48d1d9259"


class AuthError(RuntimeError):
    def __init__(self, message: str, *, status: str | None = None, raw: Any = None):
        super().__init__(message)
        self.status = status
        self.raw = raw


class AuthClient:
    def __init__(
        self,
        *,
        proxy: str | None = None,
        user_agent: str = DEFAULT_UA,
        impersonate: str = "chrome131",
        log: Callable[[str], None] | None = None,
        connect_timeout: float = 12.0,
        read_timeout: float = 25.0,
    ):
        self.proxy = (proxy or "").strip() or None
        self.user_agent = user_agent
        self.log = log or (lambda m: None)
        # (connect, read) — short connect so dead SOCKS fails fast and can rotate
        self.timeout = (float(connect_timeout), float(read_timeout))
        self.session = cf_requests.Session(impersonate=impersonate)
        self.session.headers.update({"user-agent": user_agent})

    @property
    def proxies(self) -> dict[str, str]:
        if not self.proxy:
            return {}
        return {"http": self.proxy, "https": self.proxy}

    def warm(self, redirect: str = "grok-com") -> None:
        url = f"{ACCOUNTS_BASE}/sign-up?redirect={redirect}"
        try:
            r = self.session.get(url, proxies=self.proxies, timeout=self.timeout)
        except Exception as exc:
            # Normalize so register_one retry path treats as proxy error
            raise RuntimeError(f"auth warm proxy/network error: {exc}") from exc
        self.log(f"[auth] warm {r.status_code} cookies={list(self.session.cookies.keys())}")

    def _headers(self, *, referer: str | None = None) -> dict[str, str]:
        return {
            "content-type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            "x-user-agent": "connect-es/2.1.1",
            "user-agent": self.user_agent,
            "origin": ACCOUNTS_BASE,
            "referer": referer or f"{ACCOUNTS_BASE}/sign-up?redirect=grok-com",
            "accept": "*/*",
        }

    def rpc(self, method: str, message: bytes, *, referer: str | None = None) -> dict:
        url = f"{ACCOUNTS_BASE}/{AUTH_SERVICE}/{method}"
        body = grpc_web_frame(message)
        try:
            r = self.session.post(
                url,
                data=body,
                headers=self._headers(referer=referer),
                proxies=self.proxies,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise RuntimeError(f"auth {method} proxy/network error: {exc}") from exc
        parsed = parse_grpc_web(
            r.content, {k: v for k, v in r.headers.items()}
        )
        status = parsed.get("status")
        msg = parsed.get("message") or ""
        self.log(
            f"[auth] {method} http={r.status_code} grpc={status} "
            f"msg={msg[:180]!r} frames={len(parsed.get('frames') or [])}"
        )
        # Collect sso cookies if any
        cookies = {}
        try:
            cookies = dict(self.session.cookies)
        except Exception:
            pass
        parsed["http_status"] = r.status_code
        parsed["cookies"] = cookies
        parsed["set_cookie"] = r.headers.get("set-cookie", "")
        return parsed

    def require_ok(self, result: dict, what: str) -> dict:
        status = str(result.get("status") if result.get("status") is not None else "")
        if status and status != "0":
            raise AuthError(
                f"{what} failed grpc-status={status}: {result.get('message')}",
                status=status,
                raw=result,
            )
        if int(result.get("http_status") or 0) >= 400:
            raise AuthError(
                f"{what} HTTP {result.get('http_status')}: {result.get('message')}",
                status=status,
                raw=result,
            )
        return result

    def create_email_validation_code(
        self, email: str, castle_request_token: str = ""
    ) -> dict:
        msg = build_create_email_validation_code(email, castle_request_token)
        return self.require_ok(
            self.rpc("CreateEmailValidationCode", msg),
            "CreateEmailValidationCode",
        )

    def verify_email_validation_code(self, email: str, code: str) -> dict:
        msg = build_verify_email_validation_code(email, code)
        return self.require_ok(
            self.rpc("VerifyEmailValidationCode", msg),
            "VerifyEmailValidationCode",
        )

    def create_user_and_session(
        self,
        *,
        email: str,
        password: str,
        email_validation_code: str,
        given_name: str = "John",
        family_name: str = "Doe",
        tos_accepted_version: int = 1,
        turnstile_token: str = "",
        castle_request_token: str = "",
        use_v2: bool = True,
    ) -> dict:
        msg = build_create_user_and_session(
            email=email,
            password=password,
            email_validation_code=email_validation_code,
            given_name=given_name,
            family_name=family_name,
            tos_accepted_version=tos_accepted_version,
            turnstile_token=turnstile_token,
            castle_request_token=castle_request_token,
        )
        method = "CreateUserAndSessionV2" if use_v2 else "CreateUserAndSession"
        result = self.rpc(method, msg)
        # Prefer V2; fall back to V1 if method missing.
        if str(result.get("status")) in {"12", "5"} and use_v2:
            self.log(f"[auth] {method} unavailable, fallback CreateUserAndSession")
            result = self.rpc("CreateUserAndSession", msg)
        return self.require_ok(result, "CreateUserAndSession")

    def create_session(
        self,
        *,
        email: str,
        password: str,
        turnstile_token: str = "",
        castle_request_token: str = "",
        tos_version: int | None = None,
        use_v2: bool = True,
    ) -> dict:
        """Sign-in existing user (email/password + Turnstile). Browser only solves CF.

        RPC: CreateSession / CreateSessionV2
        Returns parsed grpc-web result; SSO is in cookies or frames.session_cookie.
        """
        msg = build_create_session_request(
            email=email,
            password=password,
            turnstile_token=turnstile_token,
            castle_request_token=castle_request_token,
            tos_version=tos_version,
        )
        referer = f"{ACCOUNTS_BASE}/sign-in?redirect=grok-com"
        method = "CreateSessionV2" if use_v2 else "CreateSession"
        result = self.rpc(method, msg, referer=referer)
        if str(result.get("status")) in {"12", "5"} and use_v2:
            self.log(f"[auth] {method} unavailable, fallback CreateSession")
            result = self.rpc("CreateSession", msg, referer=referer)
        return self.require_ok(result, "CreateSession")

    def warm_sign_in(self, redirect: str = "grok-com") -> None:
        url = f"{ACCOUNTS_BASE}/sign-in?redirect={redirect}"
        try:
            r = self.session.get(url, proxies=self.proxies, timeout=self.timeout)
        except Exception as exc:
            raise RuntimeError(f"auth warm sign-in proxy/network error: {exc}") from exc
        self.log(
            f"[auth] warm sign-in {r.status_code} cookies={list(self.session.cookies.keys())}"
        )

    def set_tos_accepted_version(self, version: int = 1) -> dict:
        msg = build_set_tos_accepted_version(version)
        return self.require_ok(
            self.rpc(
                "SetTosAcceptedVersion",
                msg,
                referer=f"{ACCOUNTS_BASE}/accept-tos",
            ),
            "SetTosAcceptedVersion",
        )

    def get_sso(self) -> str:
        cookies = {}
        try:
            cookies = dict(self.session.cookies)
        except Exception:
            pass
        for key in ("sso", "sso-rw"):
            if cookies.get(key):
                return str(cookies[key])
        # try jar-style
        try:
            for c in self.session.cookies:
                name = getattr(c, "name", None) or (c[0] if isinstance(c, tuple) else None)
                value = getattr(c, "value", None) or (c[1] if isinstance(c, tuple) else None)
                if name in ("sso", "sso-rw") and value:
                    return str(value)
        except Exception:
            pass
        return ""

    def create_user_via_server_action(
        self,
        *,
        email: str,
        password: str,
        email_validation_code: str,
        turnstile_token: str,
        given_name: str = "John",
        family_name: str = "Doe",
        tos_accepted_version: int = 1,
        castle_request_token: str = "",
        conversion_id: str = "",
    ) -> dict:
        """Call the Next.js server action used by the browser signup form.

        Browser payload shape (from signup chunk):
          {
            emailValidationCode,
            createUserAndSessionRequest: {email, givenName, familyName,
                                          clearTextPassword, tosAcceptedVersion},
            turnstileToken, conversionId, castleRequestToken
          }
        """
        import json
        import uuid

        conversion_id = conversion_id or str(uuid.uuid4())
        payload = {
            "emailValidationCode": email_validation_code,
            "createUserAndSessionRequest": {
                "email": email,
                "givenName": given_name,
                "familyName": family_name,
                "clearTextPassword": password,
                "tosAcceptedVersion": tos_accepted_version,
            },
            "turnstileToken": turnstile_token,
            "conversionId": conversion_id,
            "castleRequestToken": castle_request_token or "",
        }
        # Next.js server actions accept a multipart/text body; simplest is
        # application/json with Next-Action header (works on many App Router apps).
        headers = {
            "content-type": "text/plain;charset=UTF-8",
            "next-action": CREATE_USER_SERVER_ACTION,
            "user-agent": self.user_agent,
            "origin": ACCOUNTS_BASE,
            "referer": f"{ACCOUNTS_BASE}/sign-up?redirect=grok-com",
            "accept": "text/x-component",
        }
        body = json.dumps(payload)
        # Next actions often want an array of args: [payload]
        body_arr = json.dumps([payload])
        last = None
        for candidate in (body_arr, body):
            try:
                r = self.session.post(
                    f"{ACCOUNTS_BASE}/sign-up",
                    data=candidate,
                    headers=headers,
                    proxies=self.proxies,
                    timeout=self.timeout,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"auth server-action proxy/network error: {exc}"
                ) from exc
            self.log(
                f"[auth] server-action http={r.status_code} "
                f"ct={r.headers.get('content-type','')} body={r.text[:240]!r}"
            )
            last = {
                "http_status": r.status_code,
                "text": r.text,
                "headers": dict(r.headers),
                "cookies": dict(self.session.cookies),
            }
            if r.status_code < 500:
                return last
        return last or {}


def decode_session_hints(frames: list[bytes]) -> dict[str, Any]:
    """Best-effort scan of response protobuf for string-ish session fields."""
    out: dict[str, Any] = {"strings": []}
    for fr in frames:
        try:
            fields = parse_fields(fr)
        except Exception:
            continue
        for field, wire, val in fields:
            if wire == 2 and isinstance(val, (bytes, bytearray)):
                try:
                    s = bytes(val).decode("utf-8")
                except Exception:
                    continue
                if s.isprintable() and 4 <= len(s) <= 500:
                    out["strings"].append({"field": field, "value": s[:200]})
    return out


def extract_session_cookie(frames: list[bytes]) -> str:
    """CreateSessionResponse: session=1, session_cookie=2, one_time_link_tokens=3, is_new_user=4.

    CreateSessionV2Response wraps that as field 1 (session oneof).
    Browser stores session_cookie as the `sso` / `sso-rw` cookie client-side.
    """
    for fr in frames or []:
        try:
            top = parse_fields(fr)
        except Exception:
            continue
        # V2: field 1 = CreateSessionResponse message
        candidates: list[list[tuple]] = [top]
        for field, wire, val in top:
            if field == 1 and wire == 2:
                try:
                    candidates.append(parse_fields(bytes(val)))
                except Exception:
                    pass
        for fields in candidates:
            for field, wire, val in fields:
                if field == 2 and wire == 2:
                    try:
                        s = bytes(val).decode("utf-8")
                    except Exception:
                        continue
                    if s.startswith("eyJ") and s.count(".") >= 2:
                        return s
    # fallback: any JWT-looking string in the tree
    hints = decode_session_hints(frames)
    for item in hints.get("strings") or []:
        s = str(item.get("value") or "")
        if s.startswith("eyJ") and s.count(".") >= 2:
            return s
    return ""
