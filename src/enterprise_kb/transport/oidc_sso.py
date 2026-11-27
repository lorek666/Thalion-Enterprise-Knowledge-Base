from base64 import urlsafe_b64encode
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import hmac
import json
import secrets
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import quote_plus, urlencode, urlparse

import httpx2
import jwt


TX_COOKIE = "thalion_oidc_tx"
EXCHANGE_COOKIE = "thalion_oidc_exchange"
ALLOWED_JWT_ALGORITHMS = frozenset({"RS256", "ES256"})
ALLOWED_RETURN_PREFIXES = ("/", "/manage/")


class OidcSsoError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class OidcSsoConfig:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    audience: str | None = None
    allow_http_loopback: bool = False
    state_ttl_seconds: int = 300
    ticket_ttl_seconds: int = 60
    max_pending: int = 1024
    token_auth_method: str = "client_secret_post"

    def __post_init__(self):
        for name in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_url", "redirect_uri"):
            value = getattr(self, name)
            _validate_endpoint_url(value, name, allow_http_loopback=self.allow_http_loopback)
        if not isinstance(self.client_id, str) or not self.client_id.strip():
            raise ValueError("OIDC client_id must be non-empty.")
        if not self.scopes or "openid" not in self.scopes:
            raise ValueError("OIDC scopes must include 'openid'.")
        if not 30 <= self.state_ttl_seconds <= 900:
            raise ValueError("OIDC state_ttl_seconds must be between 30 and 900.")
        if not 10 <= self.ticket_ttl_seconds <= 300:
            raise ValueError("OIDC ticket_ttl_seconds must be between 10 and 300.")
        if self.token_auth_method not in {"client_secret_post", "client_secret_basic"}:
            raise ValueError("OIDC token_auth_method must be client_secret_post or client_secret_basic.")
        if self.token_auth_method == "client_secret_basic" and not self.client_secret:
            raise ValueError("OIDC client_secret_basic requires a client secret.")


def _validate_endpoint_url(url: str, name: str, *, allow_http_loopback: bool) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"{name} must be non-empty.")
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if allow_http_loopback and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return url
    raise ValueError(f"{name} must be an HTTPS URL.")


def sanitize_return_to(raw: str | None) -> str:
    if not raw or not isinstance(raw, str):
        return "/"
    candidate = raw.strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate)
    ):
        return "/"
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return "/"
    path = parsed.path or "/"
    if path == "/" or path.startswith("/manage/"):
        return path
    return "/"


def _pkce_challenge(verifier: str) -> str:
    digest = sha256(verifier.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class _PendingAuth:
    state: str
    nonce: str
    code_verifier: str
    tx_binding: str
    return_to: str
    expires_at: float


@dataclass(frozen=True)
class _PendingTicket:
    ticket: str
    exchange_binding: str
    access_token: str
    subject: str
    expires_at_iso: str
    expires_at_mono: float


class OidcSsoManager:
    """Standard OIDC Authorization Code + PKCE (S256) flow with CSRF cookie binding and single-use ticket handoff."""

    def __init__(
        self,
        config: OidcSsoConfig,
        *,
        transport: httpx2.BaseTransport | None = None,
        timeout_seconds: float = 5.0,
        jwks_ttl_seconds: float = 300.0,
        token_mapper: Callable[[dict[str, Any], str | None], tuple[str, datetime]] | None = None,
    ):
        self.config = config
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._jwks_ttl_seconds = jwks_ttl_seconds
        self._token_mapper = token_mapper
        self._cookie_secret = secrets.token_bytes(32)
        self._lock = Lock()
        self._pending_auth: dict[str, _PendingAuth] = {}
        self._pending_tickets: dict[str, _PendingTicket] = {}
        self._keys_by_kid: dict[str, tuple[str, Any]] = {}
        self._jwks_expires_at = 0.0

    @property
    def cookie_secure(self) -> bool:
        return not self.config.allow_http_loopback

    def status_payload(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "issuer": self.config.issuer,
            "client_id": self.config.client_id,
            "login_url": "/auth/oidc/login",
        }

    def _prune_locked(self, now: float):
        expired_states = [k for k, v in self._pending_auth.items() if v.expires_at <= now]
        for key in expired_states:
            self._pending_auth.pop(key, None)
        expired_tickets = [k for k, v in self._pending_tickets.items() if v.expires_at_mono <= now]
        for key in expired_tickets:
            self._pending_tickets.pop(key, None)

    def _sign_binding(self, purpose: str, value: str) -> str:
        return hmac.new(self._cookie_secret, f"{purpose}:{value}".encode("utf-8"), sha256).hexdigest()

    def begin_login(self, return_to: str | None = None) -> tuple[str, str]:
        safe_return = sanitize_return_to(return_to)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = _pkce_challenge(code_verifier)
        tx_binding = self._sign_binding("tx", state)
        now = monotonic()
        entry = _PendingAuth(
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            tx_binding=tx_binding,
            return_to=safe_return,
            expires_at=now + self.config.state_ttl_seconds,
        )
        with self._lock:
            self._prune_locked(now)
            if len(self._pending_auth) >= self.config.max_pending:
                raise OidcSsoError("sso_busy", "登录请求过多，请稍后重试。", 503)
            self._pending_auth[state] = entry

        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        sep = "&" if "?" in self.config.authorization_endpoint else "?"
        return f"{self.config.authorization_endpoint}{sep}{urlencode(params)}", tx_binding

    def _refresh_jwks(self) -> dict[str, tuple[str, Any]]:
        try:
            with httpx2.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.get(self.config.jwks_url, headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise OidcSsoError("oidc_jwks_unavailable", "无法获取企业身份认证公钥。", 503)
            body = json.loads(response.content.decode("utf-8"))
            raw_keys = body.get("keys") if isinstance(body, dict) else None
            if not isinstance(raw_keys, list) or not raw_keys:
                raise OidcSsoError("oidc_jwks_unavailable", "企业身份认证公钥列表为空。", 503)
            parsed: dict[str, tuple[str, Any]] = {}
            for entry in raw_keys:
                if not isinstance(entry, dict):
                    continue
                kid = entry.get("kid")
                kty = entry.get("kty")
                if not isinstance(kid, str) or not kid:
                    continue
                if kty == "RSA":
                    parsed[kid] = ("RS256", jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(entry)))
                elif kty == "EC":
                    parsed[kid] = ("ES256", jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(entry)))
            if not parsed:
                raise OidcSsoError("oidc_jwks_unavailable", "未找到受支持的非对称签名公钥。", 503)
        except OidcSsoError:
            raise
        except (httpx2.HTTPError, ValueError, KeyError, TypeError, jwt.InvalidKeyError):
            raise OidcSsoError("oidc_jwks_unavailable", "企业身份认证公钥校验失败。", 503) from None

        with self._lock:
            self._keys_by_kid = parsed
            self._jwks_expires_at = monotonic() + self._jwks_ttl_seconds
        return parsed

    def _resolve_key(self, kid: str) -> tuple[str, Any] | None:
        with self._lock:
            cached = self._keys_by_kid.get(kid) if monotonic() < self._jwks_expires_at else None
        if cached is not None:
            return cached
        return self._refresh_jwks().get(kid)

    def _verify_id_token(self, id_token: str, expected_nonce: str) -> dict[str, Any]:
        if not isinstance(id_token, str) or not id_token.strip() or len(id_token) > 16_384:
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 无效。", 401)
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError:
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 格式错误。", 401) from None
        algorithm = header.get("alg")
        kid = header.get("kid")
        if algorithm not in ALLOWED_JWT_ALGORITHMS or not isinstance(kid, str) or not kid:
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 签名算法不受支持。", 401)
        resolved = self._resolve_key(kid)
        if resolved is None or resolved[0] != algorithm:
            raise OidcSsoError("oidc_invalid_token", "未匹配到有效的 OIDC 验签密钥。", 401)
        expected_aud = self.config.audience or self.config.client_id
        try:
            claims = jwt.decode(
                id_token,
                resolved[1],
                algorithms=[resolved[0]],
                audience=expected_aud,
                issuer=self.config.issuer,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat", "nonce"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.InvalidTokenError:
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 验签失败。", 401) from None
        authorized_party = claims.get("azp")
        audience = claims["aud"]
        if ("azp" in claims or (isinstance(audience, list) and len(audience) > 1)) and authorized_party != self.config.client_id:
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 不属于当前登录应用。", 401)
        try:
            datetime.fromtimestamp(float(claims["exp"]), UTC)
        except (OverflowError, OSError, ValueError, TypeError):
            raise OidcSsoError("oidc_invalid_token", "OIDC ID Token 有效期无效。", 401) from None
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, expected_nonce):
            raise OidcSsoError("oidc_nonce_mismatch", "OIDC nonce 校验失败。", 401)
        return claims

    def complete_callback(
        self,
        *,
        code: str | None,
        state: str | None,
        tx_cookie: str | None,
        idp_error: str | None = None,
    ) -> tuple[str, str]:
        if idp_error:
            raise OidcSsoError("oidc_idp_denied", "企业身份认证已拒绝或取消登录。", 401)
        if not code or not state or not tx_cookie:
            raise OidcSsoError("oidc_invalid_callback", "OIDC 回调缺少必要参数或安全绑定 Cookie。", 400)

        now = monotonic()
        with self._lock:
            self._prune_locked(now)
            pending = self._pending_auth.pop(state, None)
        if pending is None or pending.expires_at <= now:
            raise OidcSsoError("oidc_invalid_state", "OIDC 登录状态已过期或重复使用。", 401)
        if not hmac.compare_digest(tx_cookie, pending.tx_binding):
            raise OidcSsoError("oidc_csrf_mismatch", "OIDC 登录安全绑定校验失败。", 401)

        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "code_verifier": pending.code_verifier,
        }
        auth = None
        if self.config.token_auth_method == "client_secret_basic":
            auth = (quote_plus(self.config.client_id), quote_plus(self.config.client_secret))
            del form["client_id"]
        elif self.config.client_secret:
            form["client_secret"] = self.config.client_secret

        try:
            with httpx2.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.post(
                    self.config.token_endpoint,
                    data=form,
                    headers={"Accept": "application/json"},
                    auth=auth,
                )
            if response.status_code != 200:
                raise OidcSsoError("oidc_token_exchange_failed", "OIDC 授权码换取令牌失败。", 401)
            token_body = json.loads(response.content.decode("utf-8"))
        except OidcSsoError:
            raise
        except (httpx2.HTTPError, ValueError):
            raise OidcSsoError("oidc_token_exchange_failed", "OIDC 令牌端点通信失败。", 503) from None

        if not isinstance(token_body, dict):
            raise OidcSsoError("oidc_token_exchange_failed", "OIDC 令牌响应格式错误。", 401)
        id_token = token_body.get("id_token")
        raw_access_token = token_body.get("access_token")
        if not isinstance(id_token, str):
            raise OidcSsoError("oidc_invalid_token", "OIDC 响应缺少 ID Token。", 401)
        claims = self._verify_id_token(id_token, pending.nonce)
        subject = str(claims["sub"])

        if self._token_mapper is not None:
            bearer_token, expires_at = self._token_mapper(claims, raw_access_token if isinstance(raw_access_token, str) else None)
        else:
            bearer_token = raw_access_token if isinstance(raw_access_token, str) and raw_access_token.strip() else id_token
            expires_at = datetime.fromtimestamp(float(claims["exp"]), tz=UTC)

        if not isinstance(bearer_token, str) or not 32 <= len(bearer_token) <= 16_384:
            raise OidcSsoError("oidc_invalid_token", "签发的访问令牌不符合长度要求。", 401)

        ticket = secrets.token_urlsafe(32)
        exchange_binding = self._sign_binding("exchange", ticket)
        ticket_entry = _PendingTicket(
            ticket=ticket,
            exchange_binding=exchange_binding,
            access_token=bearer_token,
            subject=subject,
            expires_at_iso=expires_at.isoformat(),
            expires_at_mono=monotonic() + self.config.ticket_ttl_seconds,
        )
        with self._lock:
            self._prune_locked(monotonic())
            if len(self._pending_tickets) >= self.config.max_pending:
                raise OidcSsoError("sso_busy", "登录请求过多，请稍后重试。", 503)
            self._pending_tickets[ticket] = ticket_entry

        redirect_url = f"{pending.return_to}#oidc_ticket={ticket}"
        return redirect_url, exchange_binding

    def exchange_ticket(self, ticket: str | None, exchange_cookie: str | None) -> dict[str, str]:
        if not ticket or not isinstance(ticket, str) or not exchange_cookie:
            raise OidcSsoError("oidc_invalid_ticket", "一次性登录票据无效或缺少安全 Cookie。", 401)
        now = monotonic()
        with self._lock:
            self._prune_locked(now)
            entry = self._pending_tickets.pop(ticket, None)
        if entry is None or entry.expires_at_mono <= now:
            raise OidcSsoError("oidc_invalid_ticket", "一次性登录票据已过期或已使用。", 401)
        if not hmac.compare_digest(exchange_cookie, entry.exchange_binding):
            raise OidcSsoError("oidc_csrf_mismatch", "登录票据绑定校验失败。", 401)
        return {
            "access_token": entry.access_token,
            "subject": entry.subject,
            "expires_at": entry.expires_at_iso,
        }
