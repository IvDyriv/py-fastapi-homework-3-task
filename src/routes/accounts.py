from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)

router = APIRouter()


def _utc(dt: datetime) -> datetime:
    """SQLite може повертати naive datetime — робимо aware."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    try:
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, group.id),
        )
        db.add(user)
        await db.flush()

        db.add(ActivationTokenModel(user_id=cast(int, user.id)))

        await db.commit()
        await db.refresh(user)
        return UserRegistrationResponseSchema.model_validate(user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_row = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    if not token_row or token_row.token != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if _utc(cast(datetime, token_row.expires_at)) <= datetime.now(timezone.utc):
        await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:

    response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if not user or not user.is_active:
        return response


    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
    await db.commit()
    return response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_row = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    if not token_row or token_row.token != payload.token:
        if token_row:
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if _utc(cast(datetime, token_row.expires_at)) <= datetime.now(timezone.utc):
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:

        user.password = payload.password

        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        db.add(
            RefreshTokenModel.create(
                user_id=cast(int, user.id),
                days_valid=cast(int, settings.LOGIN_TIME_DAYS),
                token=refresh_token,
            )
        )
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = decoded.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_row = await db.scalar(select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token))
    if not token_row:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == int(user_id)))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access = jwt_manager.create_access_token({"user_id": int(user_id)})
    return TokenRefreshResponseSchema(access_token=new_access)
