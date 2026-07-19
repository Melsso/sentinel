import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.dependencies import get_current_user
from sentinel.core.logging import log_auth_event
from sentinel.core.rate_limiter import rate_limit
from sentinel.database.models import User
from sentinel.database.session import get_db
from sentinel.schemas.auth import (
    RegisterRequest,
    UserResponse,
    LoginRequest,
    EmailVerificationRequest,
    ResendVerificationEmailRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    DeleteAccountRequest,
    MessageResponse,
)
from sentinel.schemas.token import TokenResponse, RefreshTokenRequest
from sentinel.schemas.session import SessionResponse

from sentinel.core.security import create_access_token
from sentinel.services.auth import (
    authenticate_user,
    register_user,
    create_session,
    refresh_session,
    logout_user,
    verify_email,
    resend_verification_email,
    request_password_reset,
    reset_password,
    change_password,
    delete_account,
    revoke_all_sessions,
    list_active_sessions,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidSessionError,
    InvalidVerificationTokenError,
    InvalidResetTokenError,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            rate_limit(
                "register",
                "register_rate_limit",
                "register_rate_limit_window_seconds",
            )
        )
    ],
)
async def register(
    data: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user = await register_user(db, data)

    except EmailAlreadyExistsError:
        log_auth_event(
            "register_failed",
            request,
            level=logging.WARNING,
            reason="email_already_exists",
            email=data.email.strip().lower(),
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered.",
        )

    log_auth_event("register_success", request, user_id=str(user.id), email=user.email)

    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[
        Depends(
            rate_limit(
                "login",
                "login_rate_limit",
                "login_rate_limit_window_seconds",
                by_email=True,
            )
        )
    ],
)
async def login(
    data: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user = await authenticate_user(db, data)

    except InvalidCredentialsError:
        log_auth_event(
            "login_failed",
            request,
            level=logging.WARNING,
            reason="invalid_credentials",
            email=data.email.strip().lower(),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    access_token = create_access_token(str(user.id))

    refresh_token = await create_session(db, user)

    log_auth_event("login_success", request, user_id=str(user.id), email=user.email)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    data: RefreshTokenRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user, new_refresh_token = await refresh_session(
            db,
            data.refresh_token,
        )

    except InvalidRefreshTokenError:
        log_auth_event(
            "refresh_failed",
            request,
            level=logging.WARNING,
            reason="invalid_or_expired_refresh_token",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    access_token = create_access_token(str(user.id))

    log_auth_event("refresh_success", request, user_id=str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    data: RefreshTokenRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user_id = await logout_user(db, data.refresh_token)

    except InvalidSessionError:
        log_auth_event(
            "logout_failed",
            request,
            level=logging.WARNING,
            reason="unknown_or_invalid_refresh_token",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    log_auth_event("logout_success", request, user_id=str(user_id))


@router.post("/verify-email", response_model=UserResponse)
async def verify_email_route(
    data: EmailVerificationRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user = await verify_email(db, data.token)

    except InvalidVerificationTokenError:
        log_auth_event(
            "email_verification_failed",
            request,
            level=logging.WARNING,
            reason="invalid_or_expired_token",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    log_auth_event("email_verification_success", request, user_id=str(user.id))

    return user


@router.post(
    "/resend-verification-email",
    response_model=MessageResponse,
    dependencies=[
        Depends(
            rate_limit(
                "resend_verification",
                "resend_verification_rate_limit",
                "resend_verification_rate_limit_window_seconds",
                by_email=True,
            )
        )
    ],
)
async def resend_verification_email_route(
    data: ResendVerificationEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email_sent = await resend_verification_email(db, data.email)

    log_auth_event(
        "verification_email_resend_requested",
        request,
        email=data.email.strip().lower(),
        email_sent=email_sent,
    )

    return MessageResponse(
        message=(
            "If that email is registered and not yet verified, "
            "a new verification link has been sent."
        )
    )


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await list_active_sessions(db, current_user)


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    count = await revoke_all_sessions(db, current_user)

    log_auth_event(
        "logout_all_success",
        request,
        user_id=str(current_user.id),
        sessions_revoked=count,
    )

    return MessageResponse(message=f"Revoked {count} active session(s).")


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    dependencies=[
        Depends(
            rate_limit(
                "forgot_password",
                "forgot_password_rate_limit",
                "forgot_password_rate_limit_window_seconds",
                by_email=True,
            )
        )
    ],
)
async def forgot_password(
    data: ForgotPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    account_found = await request_password_reset(db, data.email)

    log_auth_event(
        "password_reset_requested",
        request,
        email=data.email.strip().lower(),
        account_found=account_found,
    )

    return MessageResponse(
        message="If that email is registered, a password reset link has been sent."
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password_route(
    data: ResetPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    try:
        user_id = await reset_password(db, data.token, data.new_password)

    except InvalidResetTokenError:
        log_auth_event(
            "password_reset_failed",
            request,
            level=logging.WARNING,
            reason="invalid_or_expired_token",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    log_auth_event("password_reset_success", request, user_id=str(user_id))

    return MessageResponse(message="Password has been reset. Please log in again.")


@router.post("/change-password", response_model=MessageResponse)
async def change_password_route(
    data: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await change_password(
            db, current_user, data.current_password, data.new_password
        )

    except InvalidCredentialsError:
        log_auth_event(
            "password_change_failed",
            request,
            level=logging.WARNING,
            reason="incorrect_current_password",
            user_id=str(current_user.id),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    log_auth_event("password_change_success", request, user_id=str(current_user.id))

    return MessageResponse(message="Password changed. Please log in again.")


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account_route(
    data: DeleteAccountRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await delete_account(db, current_user, data.password)

    except InvalidCredentialsError:
        log_auth_event(
            "account_deletion_failed",
            request,
            level=logging.WARNING,
            reason="incorrect_password",
            user_id=str(current_user.id),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password is incorrect.",
        )

    log_auth_event("account_deletion_success", request, user_id=str(current_user.id))
