from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.core.dependencies import get_current_user
from sentinel.database.models import User
from sentinel.database.session import get_db
from sentinel.schemas.auth import (
    RegisterRequest,
    UserResponse,
    LoginRequest,
    EmailVerificationRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    DeleteAccountRequest,
    MessageResponse,
)
from sentinel.schemas.token import TokenResponse, RefreshTokenRequest

from sentinel.core.security import create_access_token
from sentinel.services.auth import (
    authenticate_user,
    register_user,
    create_session,
    refresh_session,
    logout_user,
    verify_email,
    request_password_reset,
    reset_password,
    change_password,
    delete_account,
    revoke_all_sessions,
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
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await register_user(db, data)

    except EmailAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered.",
        )

    return user


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await authenticate_user(db, data)

    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    access_token = create_access_token(str(user.id))

    refresh_token = await create_session(db, user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(data: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    try:
        user, new_refresh_token = await refresh_session(
            db,
            data.refresh_token,
        )

    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    access_token = create_access_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(data: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    try:
        await logout_user(db, data.refresh_token)

    except InvalidSessionError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )


@router.post("/verify-email", response_model=UserResponse)
async def verify_email_route(
    data: EmailVerificationRequest, db: AsyncSession = Depends(get_db)
):
    try:
        user = await verify_email(db, data.token)

    except InvalidVerificationTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    return user


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    count = await revoke_all_sessions(db, current_user)

    return MessageResponse(message=f"Revoked {count} active session(s).")


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    data: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)
):
    await request_password_reset(db, data.email)

    return MessageResponse(
        message="If that email is registered, a password reset link has been sent."
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password_route(
    data: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
):
    try:
        await reset_password(db, data.token, data.new_password)

    except InvalidResetTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        )

    return MessageResponse(message="Password has been reset. Please log in again.")


@router.post("/change-password", response_model=MessageResponse)
async def change_password_route(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await change_password(
            db, current_user, data.current_password, data.new_password
        )

    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    return MessageResponse(message="Password changed. Please log in again.")


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account_route(
    data: DeleteAccountRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await delete_account(db, current_user, data.password)

    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password is incorrect.",
        )
