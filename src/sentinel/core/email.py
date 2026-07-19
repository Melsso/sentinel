import logging
from email.message import EmailMessage
from typing import Protocol

import aiosmtplib

from sentinel.config import settings


email_logger = logging.getLogger("sentinel.email")


class EmailSender(Protocol):
    async def send(self, to: str, subject: str, body: str) -> None: ...


class ConsoleEmailSender:
    async def send(self, to: str, subject: str, body: str) -> None:
        email_logger.info(
            "email_dispatched",
            extra={
                "event": "email_dispatched",
                "backend": "console",
                "to": to,
                "subject": subject,
                "body": body,
            },
        )


class SMTPEmailSender:
    def __init__(
        self,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        use_tls: bool,
        from_address: str,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._from_address = from_address

    async def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._from_address
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        await aiosmtplib.send(
            message,
            hostname=self._host,
            port=self._port,
            username=self._username,
            password=self._password,
            use_tls=self._use_tls,
        )


_sender: EmailSender | None = None


def get_email_sender() -> EmailSender:
    global _sender

    if _sender is None:
        if settings.email_backend == "smtp":
            if not settings.smtp_host:
                raise RuntimeError("EMAIL_BACKEND=smtp requires SMTP_HOST to be set.")

            _sender = SMTPEmailSender(
                host=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password,
                use_tls=settings.smtp_use_tls,
                from_address=settings.email_from,
            )
        else:
            _sender = ConsoleEmailSender()

    return _sender


async def send_email(to: str, subject: str, body: str) -> None:
    try:
        await get_email_sender().send(to, subject, body)
    except Exception:
        email_logger.exception(
            "email_send_failed",
            extra={
                "event": "email_send_failed",
                "backend": settings.email_backend,
                "to": to,
            },
        )
