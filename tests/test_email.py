import logging
from email.message import EmailMessage
from unittest.mock import AsyncMock

import pytest

import sentinel.core.email as email_module
from sentinel.config import settings
from sentinel.core.email import (
    ConsoleEmailSender,
    SMTPEmailSender,
    get_email_sender,
    send_email,
)
from sentinel.core.logging import hash_email
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_email_sender_singleton(monkeypatch):
    monkeypatch.setattr(email_module, "_sender", None)
    yield
    monkeypatch.setattr(email_module, "_sender", None)


async def test_console_sender_logs_the_email(caplog):
    sender = ConsoleEmailSender()

    with caplog.at_level(logging.INFO, logger="sentinel.email"):
        await sender.send("user@example.com", "Subject line", "Body text")

    record = next(r for r in caplog.records if r.name == "sentinel.email")
    assert record.event == "email_dispatched"
    assert record.backend == "console"
    assert record.to == "user@example.com"
    assert record.subject == "Subject line"
    assert record.body == "Body text"


async def test_console_backend_allowed_with_dev_flag(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "console")
    monkeypatch.setattr(settings, "allow_console_email", True)

    assert isinstance(get_email_sender(), ConsoleEmailSender)


async def test_console_backend_refused_without_dev_flag(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "console")
    monkeypatch.setattr(settings, "allow_console_email", False)

    with pytest.raises(RuntimeError, match="ALLOW_CONSOLE_EMAIL"):
        get_email_sender()


async def test_unknown_backend_refused(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "carrier-pigeon")

    with pytest.raises(RuntimeError, match="Unknown EMAIL_BACKEND"):
        get_email_sender()


async def test_get_email_sender_returns_smtp_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "smtp")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")

    sender = get_email_sender()

    assert isinstance(sender, SMTPEmailSender)


async def test_get_email_sender_smtp_without_host_raises(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "smtp")
    monkeypatch.setattr(settings, "smtp_host", None)

    with pytest.raises(RuntimeError):
        get_email_sender()


async def test_get_email_sender_is_cached(monkeypatch):
    monkeypatch.setattr(settings, "email_backend", "console")
    monkeypatch.setattr(settings, "allow_console_email", True)

    first = get_email_sender()
    second = get_email_sender()

    assert first is second


async def test_smtp_sender_calls_aiosmtplib_with_correct_args(monkeypatch):
    mock_send = AsyncMock()
    monkeypatch.setattr("sentinel.core.email.aiosmtplib.send", mock_send)

    sender = SMTPEmailSender(
        host="smtp.example.com",
        port=2525,
        username="user",
        password="pass",
        use_tls=True,
        from_address="no-reply@example.com",
    )

    await sender.send("someone@example.com", "Hello", "World")

    mock_send.assert_awaited_once()
    message, kwargs = mock_send.call_args.args[0], mock_send.call_args.kwargs
    assert isinstance(message, EmailMessage)
    assert message["To"] == "someone@example.com"
    assert message["From"] == "no-reply@example.com"
    assert message["Subject"] == "Hello"
    assert message.get_content().strip() == "World"
    assert kwargs == {
        "hostname": "smtp.example.com",
        "port": 2525,
        "username": "user",
        "password": "pass",
        "use_tls": True,
    }


async def test_send_email_swallows_failures_after_retrying(monkeypatch, caplog):
    monkeypatch.setattr(settings, "email_send_attempts", 3)
    monkeypatch.setattr(settings, "email_retry_base_delay_seconds", 0.0)

    class BrokenSender:
        calls = 0

        async def send(self, to: str, subject: str, body: str) -> None:
            BrokenSender.calls += 1
            raise ConnectionError("smtp server unreachable")

    monkeypatch.setattr(email_module, "_sender", BrokenSender())

    with caplog.at_level(logging.WARNING, logger="sentinel.email"):
        await send_email("user@example.com", "Subject", "Body")

    records = [r for r in caplog.records if r.name == "sentinel.email"]
    assert BrokenSender.calls == 3
    assert [r.attempt for r in records] == [1, 2, 3]
    assert records[-1].final is True
    assert records[-1].event == "email_send_failed"
    assert records[-1].to_hash == hash_email("user@example.com")
    assert not hasattr(records[-1], "to")


async def test_send_email_succeeds_after_a_transient_failure(monkeypatch):
    monkeypatch.setattr(settings, "email_send_attempts", 3)
    monkeypatch.setattr(settings, "email_retry_base_delay_seconds", 0.0)

    class FlakySender:
        calls = 0

        async def send(self, to: str, subject: str, body: str) -> None:
            FlakySender.calls += 1
            if FlakySender.calls < 2:
                raise ConnectionError("temporary")

    monkeypatch.setattr(email_module, "_sender", FlakySender())

    await send_email("user@example.com", "Subject", "Body")

    assert FlakySender.calls == 2


async def test_register_sends_verification_email(client, fake_email):
    email = unique_email()

    response = await client.post(
        "/auth/register", json={"email": email, "password": "Password123!"}
    )
    assert response.status_code == 202

    assert len(fake_email.sent) == 1
    sent = fake_email.sent[0]
    assert sent["to"] == email
    assert "verify" in sent["subject"].lower()
    assert "verify-email?token=" in sent["body"]


async def test_forgot_password_sends_reset_email_only_for_real_accounts(
    client, verified_user, fake_email
):
    user = await verified_user()
    fake_email.sent.clear()

    await client.post("/auth/forgot-password", json={"email": user["email"]})
    await client.post("/auth/forgot-password", json={"email": unique_email()})

    assert len(fake_email.sent) == 1
    sent = fake_email.sent[0]
    assert sent["to"] == user["email"]
    assert "reset" in sent["subject"].lower()
    assert "reset-password?token=" in sent["body"]
