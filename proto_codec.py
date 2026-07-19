"""Minimal protobuf / gRPC-Web helpers for xAI AuthManagement."""

from __future__ import annotations

import struct
from typing import Any
from urllib.parse import unquote


def encode_varint(n: int) -> bytes:
    out = bytearray()
    n = int(n)
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            break
    return bytes(out)


def encode_key(field: int, wire: int) -> bytes:
    return encode_varint((int(field) << 3) | int(wire))


def encode_string(field: int, value: str | bytes) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return encode_key(field, 2) + encode_varint(len(raw)) + raw


def encode_bytes(field: int, value: bytes) -> bytes:
    return encode_key(field, 2) + encode_varint(len(value)) + value


def encode_varint_field(field: int, value: int) -> bytes:
    return encode_key(field, 0) + encode_varint(value)


def encode_bool(field: int, value: bool) -> bytes:
    return encode_varint_field(field, 1 if value else 0)


def encode_message(field: int, msg: bytes) -> bytes:
    return encode_key(field, 2) + encode_varint(len(msg)) + msg


def encode_timestamp(field: int, seconds: int, nanos: int = 0) -> bytes:
    """google.protobuf.Timestamp: seconds=1, nanos=2."""
    inner = encode_varint_field(1, int(seconds))
    if nanos:
        inner += encode_varint_field(2, int(nanos))
    return encode_message(field, inner)


def grpc_web_frame(msg: bytes, compressed: bool = False) -> bytes:
    return bytes([1 if compressed else 0]) + struct.pack(">I", len(msg)) + msg


def decode_varint(buf: bytes, i: int = 0) -> tuple[int, int]:
    shift = 0
    n = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            return n, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def parse_fields(buf: bytes) -> list[tuple[int, int, Any]]:
    """Return list of (field_number, wire_type, value)."""
    i = 0
    fields: list[tuple[int, int, Any]] = []
    while i < len(buf):
        key, i = decode_varint(buf, i)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            val, i = decode_varint(buf, i)
            fields.append((field, 0, val))
        elif wire == 1:
            val = buf[i : i + 8]
            i += 8
            fields.append((field, 1, val))
        elif wire == 2:
            ln, i = decode_varint(buf, i)
            val = buf[i : i + ln]
            i += ln
            fields.append((field, 2, val))
        elif wire == 5:
            val = buf[i : i + 4]
            i += 4
            fields.append((field, 5, val))
        else:
            break
    return fields


def parse_grpc_web(content: bytes, headers: dict[str, str] | None = None) -> dict:
    """Parse a gRPC-Web / Connect-style response.

    Returns:
      {
        status: str | None,   # "0" success
        message: str,
        frames: list[bytes],  # message payloads
        trailers: dict,
      }
    """
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    status = headers.get("grpc-status")
    message = unquote(headers.get("grpc-message", "")) if headers.get("grpc-message") else ""
    frames: list[bytes] = []
    trailers: dict[str, str] = {}
    i = 0
    body = content or b""
    while i + 5 <= len(body):
        flags = body[i]
        mlen = struct.unpack(">I", body[i + 1 : i + 5])[0]
        i += 5
        data = body[i : i + mlen]
        i += mlen
        if flags & 0x80:  # trailer frame
            text = data.decode("utf-8", "replace")
            for line in text.replace("\r\n", "\n").split("\n"):
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                trailers[k.strip().lower()] = v.strip()
        else:
            frames.append(data)
    if status is None and "grpc-status" in trailers:
        status = trailers.get("grpc-status")
        message = unquote(trailers.get("grpc-message", "") or "")
    # Empty body + missing status often means success for unary empty responses.
    if status is None and not frames and not message:
        status = "0"
    return {
        "status": status,
        "message": message,
        "frames": frames,
        "trailers": trailers,
    }


# ── AuthManagement request builders ──────────────────────────────────────────
# Field numbers taken from embedded auth_mgmt.proto descriptor in accounts.x.ai JS.

def build_create_email_validation_code(email: str, castle_request_token: str = "") -> bytes:
    """CreateEmailValidationCodeRequest: email=1, email_template=2, castle_request_token=3."""
    msg = encode_string(1, email)
    if castle_request_token:
        msg += encode_string(3, castle_request_token)
    return msg


def build_verify_email_validation_code(
    email: str,
    code: str,
    *,
    delete_on_success: bool | None = None,
    return_verification_token: bool | None = None,
) -> bytes:
    """VerifyEmailValidationCodeRequest: email=1, email_validation_code=2, ..."""
    msg = encode_string(1, email) + encode_string(2, code)
    if delete_on_success is not None:
        msg += encode_bool(3, delete_on_success)
    if return_verification_token is not None:
        msg += encode_bool(4, return_verification_token)
    return msg


def build_anti_abuse_token(turnstile_token: str = "") -> bytes:
    """AntiAbuseToken: oneof token { turnstile_token = 1 }."""
    if not turnstile_token:
        return b""
    return encode_string(1, turnstile_token)


def build_create_user_request(
    *,
    email: str,
    password: str,
    given_name: str = "John",
    family_name: str = "Doe",
    tos_accepted_version: int = 1,
    birth_date_unix: int | None = None,
    turnstile_token: str = "",
) -> bytes:
    """CreateUserRequest field numbers:
      given_name=1, family_name=2, email=3, clear_text_password=5,
      tos_accepted_version=6, anti_abuse_token=7, birth_date=8
    """
    msg = (
        encode_string(1, given_name)
        + encode_string(2, family_name)
        + encode_string(3, email)
        + encode_string(5, password)
        + encode_varint_field(6, int(tos_accepted_version))
    )
    if turnstile_token:
        msg += encode_message(7, build_anti_abuse_token(turnstile_token))
    if birth_date_unix is not None:
        msg += encode_timestamp(8, int(birth_date_unix))
    return msg


def build_create_user_and_session(
    *,
    email: str,
    password: str,
    email_validation_code: str,
    given_name: str = "John",
    family_name: str = "Doe",
    tos_accepted_version: int = 1,
    turnstile_token: str = "",
    castle_request_token: str = "",
    birth_date_unix: int | None = None,
    num_one_time_links: int | None = None,
) -> bytes:
    """CreateUserAndSessionRequest:
      create_user_request=1, anti_abuse_token=6, num_one_time_links=7,
      email_validation_code=9, castle_request_token=11
    """
    user = build_create_user_request(
        email=email,
        password=password,
        given_name=given_name,
        family_name=family_name,
        tos_accepted_version=tos_accepted_version,
        birth_date_unix=birth_date_unix,
        turnstile_token=turnstile_token,
    )
    msg = encode_message(1, user)
    if turnstile_token:
        # Also attach at outer request level (used by some call sites).
        msg += encode_message(6, build_anti_abuse_token(turnstile_token))
    if num_one_time_links is not None:
        msg += encode_varint_field(7, int(num_one_time_links))
    msg += encode_string(9, email_validation_code)
    if castle_request_token:
        msg += encode_string(11, castle_request_token)
    return msg


def build_email_and_password_request(*, email: str, password: str) -> bytes:
    """CreateSessionRequest.EmailAndPasswordRequest: email=1, clear_text_password=2."""
    return encode_string(1, email) + encode_string(2, password)


def build_create_session_credentials_email_password(
    *, email: str, password: str
) -> bytes:
    """CreateSessionRequest.Credentials oneof email_and_password=1."""
    return encode_message(1, build_email_and_password_request(email=email, password=password))


def build_create_session_request(
    *,
    email: str,
    password: str,
    turnstile_token: str = "",
    castle_request_token: str = "",
    tos_version: int | None = None,
    num_one_time_links: int | None = None,
) -> bytes:
    """CreateSessionRequest (auth_mgmt.proto):

      credentials=1 (EmailAndPassword),
      anti_abuse_token=4,
      num_one_time_links=5,
      tos_version=6,
      castle_request_token=10
    """
    msg = encode_message(
        1, build_create_session_credentials_email_password(email=email, password=password)
    )
    if turnstile_token:
        msg += encode_message(4, build_anti_abuse_token(turnstile_token))
    if num_one_time_links is not None:
        msg += encode_varint_field(5, int(num_one_time_links))
    if tos_version is not None:
        msg += encode_varint_field(6, int(tos_version))
    if castle_request_token:
        msg += encode_string(10, castle_request_token)
    return msg


def build_set_tos_accepted_version(version: int = 1) -> bytes:
    """SetTosAcceptedVersionRequest — production code uses field 2 = version."""
    return encode_varint_field(2, int(version))
