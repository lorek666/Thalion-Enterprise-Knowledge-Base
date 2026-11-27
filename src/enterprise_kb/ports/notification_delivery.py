"""Ports and adapters for the unified notification delivery worker.

The worker can keep this interface stable while choosing its channel adapter.
The public entry points are ``NotificationMessage``, ``NotificationDeliveryPort``,
``SMTPNotificationDelivery``, ``IMWebhookNotificationDelivery``, and
``NotificationDeliveryConfig.from_env``.

Deployment settings are read from the environment; URLs and credentials use
indirect secret references. An absent channel is represented by ``None``.

* ``THALION_NOTIFICATION_SMTP_HOST``
* ``THALION_NOTIFICATION_SMTP_PORT``
* ``THALION_NOTIFICATION_SMTP_FROM``
* ``THALION_NOTIFICATION_SMTP_USERNAME_REF`` and ``THALION_NOTIFICATION_SMTP_PASSWORD_REF`` (optional pair)
* ``THALION_NOTIFICATION_SMTP_TIMEOUT_SECONDS`` (default 10)
* ``THALION_NOTIFICATION_IM_WEBHOOK_URL_REF``
* ``THALION_NOTIFICATION_IM_WEBHOOK_ALLOWED_HOSTS`` (comma-separated exact DNS names with optional ports, default 443)
* ``THALION_NOTIFICATION_IM_WEBHOOK_TOKEN_REF`` (optional deployment bearer token)
* ``THALION_NOTIFICATION_IM_WEBHOOK_TIMEOUT_SECONDS`` (default 5)

SMTP always uses STARTTLS. The IM webhook URL is resolved once from a secret
reference, checked against its configured target allowlist, and called with
redirect following disabled. The webhook payload is owned by this adapter and
does not accept workspace-supplied body or credential settings.
"""

from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from email.message import EmailMessage
from enum import StrEnum
from hashlib import sha256
import os
import re
import smtplib
import ssl
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx2

from enterprise_kb.runtime.config import _validate_https_url, _validate_secret_ref

from .adapters import SecretResolver, resolve_secret_ref
from .contracts import PortUnavailable


__all__ = (
    "DeliveryResult",
    "DeliveryStatus",
    "IMWebhookConfig",
    "IMWebhookNotificationDelivery",
    "NotificationDeliveryConfig",
    "NotificationDeliveryPort",
    "NotificationMessage",
    "SMTPNotificationConfig",
    "SMTPNotificationDelivery",
    "UnconfiguredNotificationDelivery",
    "parse_notification_delivery_config",
)


_DOT_ATOM = re.compile(r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9_.~+/-]{1,4094}={0,2}")


class DeliveryStatus(StrEnum):
    ACCEPTED = "accepted"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"
    UNCONFIGURED = "unconfigured"


@dataclass(frozen=True)
class DeliveryResult:
    """Accepted confirms only SMTP relay or HTTP endpoint acceptance, not receipt."""

    status: DeliveryStatus
    detail: str | None = None

    @classmethod
    def accepted(cls) -> "DeliveryResult":
        return cls(DeliveryStatus.ACCEPTED)

    @classmethod
    def retryable(cls, detail: str) -> "DeliveryResult":
        return cls(DeliveryStatus.RETRYABLE, detail)

    @classmethod
    def permanent(cls, detail: str) -> "DeliveryResult":
        return cls(DeliveryStatus.PERMANENT, detail)

    @classmethod
    def unconfigured(cls) -> "DeliveryResult":
        return cls(DeliveryStatus.UNCONFIGURED)


@dataclass(frozen=True)
class NotificationMessage:
    """Channel-neutral notification data supplied by the worker."""

    dedupe_key: str
    recipient: str = field(repr=False)
    subject: str = field(repr=False)
    body: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_text(self.dedupe_key, "dedupe_key", max_length=255)
        _require_text(self.recipient, "recipient", max_length=1_024)
        _require_text(self.subject, "subject", max_length=10_000)
        _require_text(self.body, "body", max_length=100_000)
        if any(ord(char) < 32 or ord(char) == 127 for char in self.recipient + self.subject):
            raise ValueError("Notification headers must not contain control characters.")


@runtime_checkable
class NotificationDeliveryPort(Protocol):
    def deliver(self, message: NotificationMessage) -> DeliveryResult:
        """Attempt one delivery; the worker owns persistence and retries."""


class UnconfiguredNotificationDelivery:
    def deliver(self, message: NotificationMessage) -> DeliveryResult:
        return DeliveryResult.unconfigured()


@dataclass(frozen=True)
class SMTPNotificationConfig:
    host: str
    port: int
    sender: str
    username_ref: str | None = None
    password_ref: str | None = None
    timeout_seconds: float = 10.0
    tls: bool = True

    def __post_init__(self) -> None:
        if not _is_hostname(self.host):
            raise ValueError("SMTP host must be a hostname without a scheme or port.")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65_535:
            raise ValueError("SMTP port must be an integer between 1 and 65535.")
        _validate_email(self.sender, "sender")
        username_ref, password_ref = self.username_ref, self.password_ref
        if (username_ref is None) != (password_ref is None):
            raise ValueError("SMTP username_ref and password_ref must both be provided together.")
        if username_ref is not None and password_ref is not None:
            _validate_secret_ref(username_ref, "username_ref")
            _validate_secret_ref(password_ref, "password_ref")
        _validate_timeout(self.timeout_seconds, "SMTP timeout_seconds")
        if self.tls is not True:
            raise ValueError("SMTP TLS is mandatory.")


@dataclass(frozen=True)
class IMWebhookConfig:
    url_ref: str
    allowed_hosts: tuple[str, ...]
    token_ref: str | None = None
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        _validate_secret_ref(self.url_ref, "url_ref")
        if not isinstance(self.allowed_hosts, tuple) or not self.allowed_hosts:
            raise ValueError("IM webhook allowed_hosts must not be empty.")
        normalised = tuple(_normalise_target(value) for value in self.allowed_hosts)
        if len(set(normalised)) != len(normalised):
            raise ValueError("IM webhook allowed_hosts must be unique.")
        if self.token_ref is not None:
            _validate_secret_ref(self.token_ref, "token_ref")
        _validate_timeout(self.timeout_seconds, "IM webhook timeout_seconds")


@dataclass(frozen=True)
class NotificationDeliveryConfig:
    smtp: SMTPNotificationConfig | None = None
    im_webhook: IMWebhookConfig | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "NotificationDeliveryConfig":
        env = os.environ if environ is None else environ
        return cls(
            smtp=_smtp_config_from_env(env),
            im_webhook=_im_webhook_config_from_env(env),
        )


def parse_notification_delivery_config(
    environ: Mapping[str, str] | None = None,
) -> NotificationDeliveryConfig:
    """Parse deployment-only notification configuration from environment."""

    return NotificationDeliveryConfig.from_env(environ)


class SMTPNotificationDelivery:
    def __init__(
        self,
        config: SMTPNotificationConfig,
        *,
        environ: Mapping[str, str] | None = None,
        secret_resolver: SecretResolver | None = None,
        smtp_factory: Callable[..., smtplib.SMTP] | None = None,
    ):
        self._config = config
        self._environ = environ
        self._secret_resolver = secret_resolver
        self._smtp_factory = smtplib.SMTP if smtp_factory is None else smtp_factory

    @classmethod
    def unconfigured(cls) -> UnconfiguredNotificationDelivery:
        return UnconfiguredNotificationDelivery()

    def deliver(self, message: NotificationMessage) -> DeliveryResult:
        try:
            recipient = _validate_email(message.recipient, "recipient")
        except ValueError:
            return DeliveryResult.permanent("SMTP recipient is invalid.")
        try:
            credentials = self._credentials()
        except (PortUnavailable, ValueError):
            return DeliveryResult.permanent("SMTP credentials are unavailable.")
        except OSError:
            return DeliveryResult.retryable("SMTP credentials are temporarily unavailable.")

        email = EmailMessage()
        email["From"] = self._config.sender
        email["To"] = recipient
        email["Subject"] = message.subject
        sender_domain = self._config.sender.rsplit("@", 1)[1]
        email["Message-ID"] = f"<{_idempotency_key(message.dedupe_key)}@{sender_domain}>"
        email.set_content(message.body)

        connection = None
        try:
            connection = self._smtp_factory(
                self._config.host,
                self._config.port,
                timeout=self._config.timeout_seconds,
            )
            connection.ehlo()
            connection.starttls(context=ssl.create_default_context())
            connection.ehlo()
            if credentials is not None:
                connection.login(*credentials)
            refused = connection.send_message(email)
            if refused:
                return _smtp_refused_result(refused)
            return DeliveryResult.accepted()
        except (OSError, ValueError) as exc:
            return _smtp_exception_result(exc)
        finally:
            if connection is not None:
                try:
                    connection.quit()
                except OSError:
                    with suppress(OSError):
                        connection.close()

    def _credentials(self) -> tuple[str, str] | None:
        username_ref = self._config.username_ref
        password_ref = self._config.password_ref
        if username_ref is None or password_ref is None:
            return None
        credentials = (
            resolve_secret_ref(
                username_ref,
                environ=self._environ,
                external_resolver=self._secret_resolver,
            ),
            resolve_secret_ref(
                password_ref,
                environ=self._environ,
                external_resolver=self._secret_resolver,
            ),
        )
        if any(len(value) > 4096 or any(not 32 <= ord(char) <= 126 for char in value) for value in credentials):
            raise ValueError("Invalid SMTP credential.")
        return credentials


class IMWebhookNotificationDelivery:
    def __init__(
        self,
        config: IMWebhookConfig,
        *,
        environ: Mapping[str, str] | None = None,
        secret_resolver: SecretResolver | None = None,
        transport: httpx2.BaseTransport | None = None,
    ):
        self._config = config
        self._environ = environ
        self._secret_resolver = secret_resolver
        self._transport = transport
        try:
            raw_url = resolve_secret_ref(
                config.url_ref,
                environ=environ,
                external_resolver=secret_resolver,
            )
        except (PortUnavailable, ValueError, OSError):
            raise PortUnavailable("IM webhook URL is unavailable.") from None
        self._url = _fixed_webhook_url(raw_url, config.allowed_hosts)

    @classmethod
    def unconfigured(cls) -> UnconfiguredNotificationDelivery:
        return UnconfiguredNotificationDelivery()

    def deliver(self, message: NotificationMessage) -> DeliveryResult:
        headers = {
            "Accept": "application/json",
            "Idempotency-Key": _idempotency_key(message.dedupe_key),
        }
        try:
            token = self._token()
        except (PortUnavailable, ValueError):
            return DeliveryResult.permanent("IM webhook credentials are unavailable.")
        except OSError:
            return DeliveryResult.retryable("IM webhook credentials are temporarily unavailable.")
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"

        try:
            with httpx2.Client(
                timeout=self._config.timeout_seconds,
                transport=self._transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST",
                    self._url,
                    headers=headers,
                    json={"text": "Thalion 有新通知，请登录查看。"},
                ) as response:
                    status_code = response.status_code
        except httpx2.HTTPError:
            return DeliveryResult.retryable("IM webhook request failed.")

        return _http_result(status_code)

    def _token(self) -> str | None:
        if self._config.token_ref is None:
            return None
        token = resolve_secret_ref(
            self._config.token_ref,
            environ=self._environ,
            external_resolver=self._secret_resolver,
        )
        if not _BEARER_TOKEN.fullmatch(token):
            raise PortUnavailable("IM webhook credential is invalid.")
        return token


def _require_text(value: str, label: str, *, max_length: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{label} must be a non-empty string of at most {max_length} characters.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{label} must be valid UTF-8 text.") from None


def _validate_timeout(value: float, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 120:
        raise ValueError(f"{label} must be greater than 0 and at most 120 seconds.")


def _is_hostname(host: str) -> bool:
    return isinstance(host, str) and 0 < len(host) <= 253 and all(
        _DNS_LABEL.fullmatch(label) for label in host.split(".")
    )


def _validate_email(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value) > 254:
        raise ValueError(f"{label} must be a valid email address.")
    local, separator, domain = value.partition("@")
    if not (separator and len(local) <= 64 and _DOT_ATOM.fullmatch(local) and "." in domain and _is_hostname(domain)):
        raise ValueError(f"{label} must be a valid email address.")
    return value


def _normalise_target(value: str) -> tuple[str, int]:
    host, separator, port_text = value.partition(":") if isinstance(value, str) else ("", "", "")
    if not _is_hostname(host) or (separator and not re.fullmatch(r"[0-9]{1,5}", port_text)):
        raise ValueError("IM webhook allowed target must be a hostname with an optional port.")
    port = int(port_text) if separator else 443
    if not 1 <= port <= 65_535:
        raise ValueError("IM webhook allowed target port must be between 1 and 65535.")
    return host.lower(), port


def _fixed_webhook_url(raw_url: str, allowed_hosts: tuple[str, ...]) -> httpx2.URL:
    if any(char in "#\\" or char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw_url):
        raise ValueError("IM webhook URL contains forbidden characters.")
    try:
        url = _validate_https_url(raw_url, "IM webhook URL")
        target = _normalise_target(urlsplit(url).netloc)
        parsed = httpx2.URL(url)
    except (ValueError, httpx2.InvalidURL):
        raise ValueError("IM webhook URL must use HTTPS with a valid target and no URL userinfo.") from None
    if target not in {_normalise_target(host) for host in allowed_hosts}:
        raise ValueError("IM webhook URL is outside the configured allowed target.")
    return parsed


def _smtp_config_from_env(env: Mapping[str, str]) -> SMTPNotificationConfig | None:
    prefix = "THALION_NOTIFICATION_SMTP_"
    if not any(key.startswith(prefix) and value for key, value in env.items()):
        return None
    username_ref = env.get(f"{prefix}USERNAME_REF", "").strip() or None
    password_ref = env.get(f"{prefix}PASSWORD_REF", "").strip() or None
    if (username_ref is None) != (password_ref is None):
        raise ValueError(f"{prefix}USERNAME_REF and {prefix}PASSWORD_REF must both be set or both omitted.")
    return SMTPNotificationConfig(
        host=_required_env(env, f"{prefix}HOST"),
        port=_parse_int_env(env, f"{prefix}PORT"),
        sender=_required_env(env, f"{prefix}FROM"),
        username_ref=username_ref,
        password_ref=password_ref,
        timeout_seconds=_timeout_env(env, f"{prefix}TIMEOUT_SECONDS", 10.0),
    )


def _im_webhook_config_from_env(env: Mapping[str, str]) -> IMWebhookConfig | None:
    prefix = "THALION_NOTIFICATION_IM_WEBHOOK_"
    if not any(key.startswith(prefix) and value for key, value in env.items()):
        return None
    hosts = tuple(
        value.strip()
        for value in _required_env(env, f"{prefix}ALLOWED_HOSTS").split(",")
        if value.strip()
    )
    return IMWebhookConfig(
        url_ref=_required_env(env, f"{prefix}URL_REF"),
        allowed_hosts=hosts,
        token_ref=env.get(f"{prefix}TOKEN_REF", "").strip() or None,
        timeout_seconds=_timeout_env(env, f"{prefix}TIMEOUT_SECONDS", 5.0),
    )


def _required_env(env: Mapping[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise ValueError(f"{key} is required when notification delivery is configured.")
    return value


def _parse_int_env(env: Mapping[str, str], key: str) -> int:
    raw = _required_env(env, key)
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{key} must be an integer.") from None


def _timeout_env(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env.get(key, "").strip() or default)
    except ValueError:
        raise ValueError(f"{key} must be a number of seconds.") from None


def _smtp_exception_result(exc: BaseException) -> DeliveryResult:
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return _smtp_refused_result(exc.recipients)
    if isinstance(exc, (smtplib.SMTPNotSupportedError, ssl.SSLError, ValueError)):
        return DeliveryResult.permanent("SMTP cannot deliver the notification.")
    if isinstance(exc, smtplib.SMTPResponseException) and 500 <= exc.smtp_code <= 599:
        return DeliveryResult.permanent("SMTP rejected the notification.")
    return DeliveryResult.retryable("SMTP is temporarily unavailable.")


def _idempotency_key(dedupe_key: str) -> str:
    return sha256(dedupe_key.encode("utf-8")).hexdigest()


def _smtp_refused_result(refused: Mapping[str, tuple[int, bytes]]) -> DeliveryResult:
    if any(500 <= code <= 599 for code, _diagnostic in refused.values()):
        return DeliveryResult.permanent("SMTP rejected the notification recipient.")
    return DeliveryResult.retryable("SMTP temporarily refused the notification recipient.")


def _http_result(status_code: int) -> DeliveryResult:
    if 200 <= status_code <= 299:
        return DeliveryResult.accepted()
    if status_code in {408, 425, 429} or 500 <= status_code <= 599:
        return DeliveryResult.retryable(f"IM webhook returned retryable HTTP {status_code}.")
    return DeliveryResult.permanent(f"IM webhook returned permanent HTTP {status_code}.")
