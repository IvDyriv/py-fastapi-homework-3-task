from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class MessageResponseSchema(BaseModel):
    message: str


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
