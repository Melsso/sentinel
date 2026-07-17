from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.database.session import get_db
from sentinel.schemas.auth import (
    RegisterRequest,
    UserResponse,
    LoginRequest,
    EmailVerificationRequest,
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
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    InvalidSessionError,
    InvalidVerificationTokenError,
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
