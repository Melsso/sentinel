from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.database.session import get_db
from sentinel.schemas.auth import RegisterRequest, UserResponse, LoginRequest
from sentinel.schemas.token import TokenResponse

from sentinel.core.security import create_access_token
from sentinel.services.auth import (
    authenticate_user,
    register_user,
    create_session,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
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
