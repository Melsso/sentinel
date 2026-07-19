import pytest

from sentinel.database.models import AuthProvider
from sentinel.core.security import password_hasher
from tests.conftest import unique_email


pytestmark = pytest.mark.asyncio

_GENERIC_MESSAGE = (
    "If that email is registered and not yet verified, "
    "a new verification link has been sent."
)


async def test_resend_verification_sends_new_token(
    client, register, find_verification_token, fake_email
):
    email, _, resp = await register(email=unique_email())
    user_id = resp.json()["id"]
    first_token = find_verification_token(user_id)
    fake_email.sent.clear()

    response = await client.post(
        "/auth/resend-verification-email", json={"email": email}
    )

    assert response.status_code == 200
    assert response.json()["message"] == _GENERIC_MESSAGE

    assert len(fake_email.sent) == 1
    assert fake_email.sent[0]["to"] == email

    second_token = find_verification_token(user_id)
    assert second_token is not None
    verify_original = await client.post(
        "/auth/verify-email", json={"token": first_token}
    )
    assert verify_original.status_code == 200


async def test_resend_verification_actually_verifies_with_new_token(
    client, register, find_verification_token
):
    email, _, resp = await register(email=unique_email())
    user_id = resp.json()["id"]

    await client.post("/auth/resend-verification-email", json={"email": email})
    token = find_verification_token(user_id)

    verify = await client.post("/auth/verify-email", json={"token": token})
    assert verify.status_code == 200
    assert verify.json()["is_verified"] is True


async def test_resend_verification_unknown_email_same_response(client, fake_email):
    response = await client.post(
        "/auth/resend-verification-email", json={"email": unique_email()}
    )

    assert response.status_code == 200
    assert response.json()["message"] == _GENERIC_MESSAGE
    assert len(fake_email.sent) == 0


async def test_resend_verification_already_verified_same_response(
    client, verified_user, fake_email
):
    user = await verified_user()
    fake_email.sent.clear()

    response = await client.post(
        "/auth/resend-verification-email", json={"email": user["email"]}
    )

    assert response.status_code == 200
    assert response.json()["message"] == _GENERIC_MESSAGE
    assert len(fake_email.sent) == 0


async def test_resend_verification_deleted_account_no_email(
    client, make_db_user, fake_email
):
    user = await make_db_user(
        password_hash=password_hasher.hash("Password123!"),
        is_verified=False,
        is_deleted=True,
    )

    response = await client.post(
        "/auth/resend-verification-email", json={"email": user.email}
    )

    assert response.status_code == 200
    assert response.json()["message"] == _GENERIC_MESSAGE
    assert len(fake_email.sent) == 0


async def test_resend_verification_oauth_account_no_email(
    client, make_db_user, fake_email
):
    user = await make_db_user(
        provider=AuthProvider.GOOGLE,
        provider_user_id="sub-123",
        is_verified=False,
    )

    response = await client.post(
        "/auth/resend-verification-email", json={"email": user.email}
    )

    assert response.status_code == 200
    assert response.json()["message"] == _GENERIC_MESSAGE
    assert len(fake_email.sent) == 0
