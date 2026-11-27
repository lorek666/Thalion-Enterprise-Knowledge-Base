from email.message import EmailMessage
from hashlib import sha256
import json
import smtplib
import ssl

import httpx2
import pytest


def test_notification_message_and_result_have_stable_contract():
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        DeliveryResult,
        NotificationMessage,
    )

    message = NotificationMessage(
        dedupe_key="task-123:assigned",
        recipient="owner@example.com",
        subject="Task assigned",
        body="A task needs your attention.",
    )

    assert message.dedupe_key == "task-123:assigned"
    assert DeliveryResult.accepted().status is DeliveryStatus.ACCEPTED
    assert DeliveryResult.retryable("temporary outage").status is DeliveryStatus.RETRYABLE
    assert DeliveryResult.permanent("invalid recipient").status is DeliveryStatus.PERMANENT
    assert DeliveryResult.unconfigured().status is DeliveryStatus.UNCONFIGURED


def test_notification_message_validates_delivery_inputs():
    from enterprise_kb.ports.notification_delivery import NotificationMessage

    with pytest.raises(ValueError, match="dedupe_key"):
        NotificationMessage("", "owner@example.com", "Subject", "Body")
    with pytest.raises(ValueError, match="recipient"):
        NotificationMessage("key", "", "Subject", "Body")
    with pytest.raises(ValueError, match="subject"):
        NotificationMessage("key", "owner@example.com", "", "Body")
    with pytest.raises(ValueError, match="body"):
        NotificationMessage("key", "owner@example.com", "Subject", "")


def test_smtp_adapter_uses_starttls_and_reports_acceptance(monkeypatch):
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        NotificationMessage,
        SMTPNotificationConfig,
        SMTPNotificationDelivery,
    )

    class FakeSMTP:
        def __init__(self, host, port, *, timeout):
            self.connection = (host, port, timeout)
            self.calls = []
            self.sent = None

        def ehlo(self):
            self.calls.append("ehlo")

        def starttls(self, *, context):
            assert context.check_hostname
            assert context.verify_mode == ssl.CERT_REQUIRED
            self.calls.append("starttls")

        def login(self, username, password):
            assert (username, password) == ("mailer", "smtp-test-password")
            self.calls.append("login")

        def send_message(self, message):
            self.sent = message
            self.calls.append("send_message")
            return {}

        def quit(self):
            self.calls.append("quit")
            raise smtplib.SMTPServerDisconnected("connection closed after DATA accepted")

        def close(self):
            self.calls.append("close")

    smtp_connections = []

    def smtp_factory(host, port, *, timeout):
        connection = FakeSMTP(host, port, timeout=timeout)
        smtp_connections.append(connection)
        return connection

    monkeypatch.setattr(smtplib, "SMTP", smtp_factory)
    adapter = SMTPNotificationDelivery(
        SMTPNotificationConfig(
            host="smtp.example.com",
            port=587,
            sender="no-reply@example.com",
            username_ref="env:SMTP_USER",
            password_ref="env:SMTP_PASSWORD",
        ),
        environ={"SMTP_USER": "mailer", "SMTP_PASSWORD": "smtp-test-password"},
    )

    result = adapter.deliver(
        NotificationMessage("task-123:assigned", "owner@example.com", "Subject", "Body")
    )

    assert result.status is DeliveryStatus.ACCEPTED
    connection = smtp_connections[0]
    assert connection.connection == ("smtp.example.com", 587, 10.0)
    assert connection.calls == ["ehlo", "starttls", "ehlo", "login", "send_message", "quit", "close"]
    assert isinstance(connection.sent, EmailMessage)
    assert connection.sent["To"] == "owner@example.com"
    assert connection.sent.get_content() == "Body\n"
    assert connection.sent["Message-ID"] == (
        f"<{sha256(b'task-123:assigned').hexdigest()}@example.com>"
    )


@pytest.mark.parametrize(("error", "status"), [
    (TimeoutError("upstream diagnostic"), "retryable"),
    (smtplib.SMTPDataError(451, b"upstream diagnostic"), "retryable"),
    (smtplib.SMTPRecipientsRefused({"owner@example.com": (450, b"upstream diagnostic")}), "retryable"),
    (smtplib.SMTPRecipientsRefused({"owner@example.com": (550, b"upstream diagnostic")}), "permanent"),
    (smtplib.SMTPAuthenticationError(535, b"upstream diagnostic"), "permanent"),
    (smtplib.SMTPNotSupportedError("upstream diagnostic"), "permanent"),
    (ssl.SSLCertVerificationError("upstream diagnostic"), "permanent"),
])
def test_smtp_adapter_distinguishes_retryable_and_permanent_failures(error, status):
    from enterprise_kb.ports.notification_delivery import (
        NotificationMessage,
        SMTPNotificationConfig,
        SMTPNotificationDelivery,
    )

    class FailingSMTP:
        def ehlo(self):
            return None

        def starttls(self, *, context):
            return None

        def send_message(self, message):
            raise error

        def quit(self):
            return None

        def close(self):
            return None

    config = SMTPNotificationConfig(
        host="smtp.example.com",
        port=587,
        sender="no-reply@example.com",
        username_ref=None,
        password_ref=None,
    )
    message = NotificationMessage("key", "owner@example.com", "Subject", "Body")

    result = SMTPNotificationDelivery(
        config,
        smtp_factory=lambda *_, **__: FailingSMTP(),
    ).deliver(message)

    assert result.status == status
    assert "upstream diagnostic" not in result.detail


def test_smtp_invalid_recipient_or_auth_does_not_connect():
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        NotificationMessage,
        SMTPNotificationConfig,
        SMTPNotificationDelivery,
    )

    adapter = SMTPNotificationDelivery(
        SMTPNotificationConfig("smtp.example.com", 587, "from@example.com", "env:SMTP_USER", "env:SMTP_SECRET"),
        environ={"SMTP_USER": "mailer", "SMTP_SECRET": "non-ASCII-é"},
        smtp_factory=lambda *_args, **_kwargs: pytest.fail("Invalid input must not connect"),
    )
    for recipient in ("owner@example.com,other@example.com", "owner@example.com"):
        assert adapter.deliver(NotificationMessage("key", recipient, "Subject", "Body")).status is DeliveryStatus.PERMANENT


def test_smtp_configuration_rejects_invalid_parameters():
    from enterprise_kb.ports.notification_delivery import SMTPNotificationConfig

    with pytest.raises(ValueError, match="port"):
        SMTPNotificationConfig("smtp.example.com", 0, "from@example.com", None, None)
    with pytest.raises(ValueError, match="sender"):
        SMTPNotificationConfig("smtp.example.com", 587, "invalid", None, None)
    with pytest.raises(ValueError, match="TLS"):
        SMTPNotificationConfig(
            "smtp.example.com", 587, "from@example.com", None, None, tls=False
        )
    with pytest.raises(ValueError, match="both"):
        SMTPNotificationConfig(
            "smtp.example.com", 587, "from@example.com", "env:SMTP_USER", None
        )
    with pytest.raises(ValueError, match="host"):
        SMTPNotificationConfig("smtp.example.com:587", 587, "from@example.com", None, None)
    with pytest.raises(ValueError, match="timeout"):
        SMTPNotificationConfig("smtp.example.com", 587, "from@example.com", None, None, timeout_seconds=float("nan"))


def test_notification_config_from_env_requires_indirect_secrets_and_supports_none():
    from enterprise_kb.ports.notification_delivery import NotificationDeliveryConfig

    assert NotificationDeliveryConfig.from_env({}).smtp is None
    assert NotificationDeliveryConfig.from_env({}).im_webhook is None

    with pytest.raises(ValueError, match="PASSWORD_REF"):
        NotificationDeliveryConfig.from_env(
            {
                "THALION_NOTIFICATION_SMTP_HOST": "smtp.example.com",
                "THALION_NOTIFICATION_SMTP_PORT": "587",
                "THALION_NOTIFICATION_SMTP_FROM": "no-reply@example.com",
                "THALION_NOTIFICATION_SMTP_USERNAME_REF": "env:SMTP_USER",
            }
        )

    with pytest.raises(ValueError, match="raw secret"):
        NotificationDeliveryConfig.from_env(
            {
                "THALION_NOTIFICATION_SMTP_HOST": "smtp.example.com",
                "THALION_NOTIFICATION_SMTP_PORT": "587",
                "THALION_NOTIFICATION_SMTP_FROM": "no-reply@example.com",
                "THALION_NOTIFICATION_SMTP_USERNAME_REF": "mailer",
                "THALION_NOTIFICATION_SMTP_PASSWORD_REF": "env:SMTP_PASSWORD",
            }
        )

    parsed = NotificationDeliveryConfig.from_env(
        {
            "THALION_NOTIFICATION_SMTP_HOST": "smtp.example.com",
            "THALION_NOTIFICATION_SMTP_PORT": "587",
            "THALION_NOTIFICATION_SMTP_FROM": "no-reply@example.com",
            "THALION_NOTIFICATION_SMTP_USERNAME_REF": "env:SMTP_USER",
            "THALION_NOTIFICATION_SMTP_PASSWORD_REF": "env:SMTP_PASSWORD",
            "THALION_NOTIFICATION_IM_WEBHOOK_URL_REF": "env:IM_WEBHOOK_URL",
            "THALION_NOTIFICATION_IM_WEBHOOK_ALLOWED_HOSTS": "hooks.example.com",
            "THALION_NOTIFICATION_IM_WEBHOOK_TOKEN_REF": "env:IM_WEBHOOK_TOKEN",
        }
    )
    assert parsed.smtp.host == "smtp.example.com"
    assert parsed.smtp.port == 587
    assert parsed.im_webhook.allowed_hosts == ("hooks.example.com",)

    relay = NotificationDeliveryConfig.from_env({
        "THALION_NOTIFICATION_SMTP_HOST": "smtp.example.com",
        "THALION_NOTIFICATION_SMTP_PORT": "587",
        "THALION_NOTIFICATION_SMTP_FROM": "no-reply@example.com",
    })
    assert relay.smtp.username_ref is None and relay.smtp.password_ref is None

    with pytest.raises(ValueError, match="raw secret"):
        NotificationDeliveryConfig.from_env(
            {
                "THALION_NOTIFICATION_IM_WEBHOOK_URL_REF": "env:IM_WEBHOOK_URL",
                "THALION_NOTIFICATION_IM_WEBHOOK_ALLOWED_HOSTS": "hooks.example.com",
                "THALION_NOTIFICATION_IM_WEBHOOK_TOKEN_REF": "inline-token",
            }
        )


def test_im_webhook_posts_fixed_payload_without_workspace_values_and_with_idempotency_key(caplog):
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        IMWebhookConfig,
        IMWebhookNotificationDelivery,
        NotificationMessage,
    )

    requests = []

    class UnreadableBody(httpx2.SyncByteStream):
        def __iter__(self):
            pytest.fail("Webhook response body must not be read")

    def handler(request):
        requests.append(request)
        return httpx2.Response(202, stream=UnreadableBody())

    caplog.set_level("INFO", logger="httpx2")
    adapter = IMWebhookNotificationDelivery(
        IMWebhookConfig(
            url_ref="env:IM_WEBHOOK_URL",
            allowed_hosts=("hooks.example.com",),
            token_ref="env:IM_WEBHOOK_TOKEN",
        ),
        environ={
            "IM_WEBHOOK_URL": "https://hooks.example.com/notify?key=private-url-key",
            "IM_WEBHOOK_TOKEN": "webhook-token",
        },
        transport=httpx2.MockTransport(handler),
    )
    message = NotificationMessage("key with workspace data", "workspace-owner", "Subject", "Body")
    for _attempt in range(2):
        assert adapter.deliver(message).status is DeliveryStatus.ACCEPTED

    assert len(requests) == 2
    for request in requests:
        assert request.method == "POST"
        assert str(request.url) == "https://hooks.example.com/notify?key=private-url-key"
        assert request.headers["Idempotency-Key"] == sha256(message.dedupe_key.encode()).hexdigest()
        assert request.headers["Authorization"] == "Bearer webhook-token"
        assert json.loads(request.content) == {"text": "Thalion 有新通知，请登录查看。"}
        request_text = request.content.decode()
        assert all(value not in request_text for value in (message.recipient, message.subject, message.body, "webhook-token"))
        assert message.recipient not in str(request.url)
    assert "private-url-key" not in caplog.text


def test_im_webhook_rejects_redirects_wrong_targets_and_classifies_http_errors():
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        IMWebhookConfig,
        IMWebhookNotificationDelivery,
        NotificationMessage,
    )

    with pytest.raises(ValueError, match="allowed"):
        IMWebhookNotificationDelivery(
            IMWebhookConfig(
                url_ref="env:IM_WEBHOOK_URL",
                allowed_hosts=("hooks.example.com",),
            ),
            environ={"IM_WEBHOOK_URL": "https://other.example.com/notify"},
        )

    message = NotificationMessage("key", "workspace-owner", "Subject", "Body")
    config = IMWebhookConfig(
        url_ref="env:IM_WEBHOOK_URL",
        allowed_hosts=("hooks.example.com",),
    )

    def response(status):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx2.Response(302, headers={"Location": "https://other.example.com"}) if status == 302 else httpx2.Response(status)

        result = IMWebhookNotificationDelivery(
            config,
            environ={"IM_WEBHOOK_URL": "https://hooks.example.com/notify"},
            transport=httpx2.MockTransport(handler),
        ).deliver(message)
        assert len(requests) == 1
        return result

    assert response(429).status is DeliveryStatus.RETRYABLE
    assert response(503).status is DeliveryStatus.RETRYABLE
    assert response(400).status is DeliveryStatus.PERMANENT
    assert response(302).status is DeliveryStatus.PERMANENT


@pytest.mark.parametrize("url", [
    "http://hooks.example.com/path",
    "https://hooks.example.com:0/path",
    "https://hooks.example.com:8443/path",
    "https://hooks.example.com:/path",
    "https://@hooks.example.com/path",
    "https://hooks.example.com/path#",
    "https://hooks.example.com/pa\tth",
])
def test_im_webhook_rejects_unsafe_urls(url):
    from enterprise_kb.ports.notification_delivery import IMWebhookConfig, IMWebhookNotificationDelivery

    with pytest.raises(ValueError):
        IMWebhookNotificationDelivery(
            IMWebhookConfig("env:IM_WEBHOOK_URL", ("hooks.example.com",)),
            environ={"IM_WEBHOOK_URL": url},
        )


def test_im_webhook_has_unconfigured_result_and_no_workspace_credentials_or_body_config():
    from enterprise_kb.ports.notification_delivery import (
        DeliveryStatus,
        IMWebhookNotificationDelivery,
        NotificationMessage,
    )

    result = IMWebhookNotificationDelivery.unconfigured().deliver(
        NotificationMessage("key", "workspace-owner", "Subject", "Body")
    )

    assert result.status is DeliveryStatus.UNCONFIGURED
