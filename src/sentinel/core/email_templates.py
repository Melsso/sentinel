from sentinel.config import settings


def verification_email(token: str) -> tuple[str, str]:
    link = f"{settings.frontend_url}/verify-email?token={token}"

    subject = "Verify your email"
    body = (
        "Welcome! Please verify your email address by visiting the link "
        f"below:\n\n{link}\n\n"
        f"This link expires in {settings.email_verification_expire_minutes} "
        "minutes. If you didn't create this account, you can ignore this "
        "email."
    )

    return subject, body


def password_reset_email(token: str) -> tuple[str, str]:
    link = f"{settings.frontend_url}/reset-password?token={token}"

    subject = "Reset your password"
    body = (
        "We received a request to reset your password. Visit the link "
        f"below to choose a new one:\n\n{link}\n\n"
        f"This link expires in {settings.password_reset_expire_minutes} "
        "minutes. If you didn't request this, you can safely ignore this "
        "email -- your password will not be changed."
    )

    return subject, body


def account_exists_email() -> tuple[str, str]:
    link = f"{settings.frontend_url}/forgot-password"

    subject = "Someone tried to register with your email"
    body = (
        "Someone just tried to create an account with this email address, "
        "but an account already exists.\n\n"
        "If that was you, log in as usual, or reset your password here:"
        f"\n\n{link}\n\n"
        "If it wasn't you, you can safely ignore this email."
    )

    return subject, body
