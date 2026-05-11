"""
User and authentication models for the High School Management System
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)


class UserRegister(UserBase):
    """User registration request model"""
    password: str = Field(..., min_length=8, max_length=100)


class UserLogin(BaseModel):
    """User login request model"""
    email: EmailStr
    password: str


class UserResponse(UserBase):
    """User response model"""
    user_id: str
    created_at: datetime
    role: str = "student"

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class User(UserBase):
    """User database model"""
    user_id: str
    hashed_password: str
    created_at: datetime
    updated_at: datetime
    role: str = "student"  # 'student', 'admin', 'staff'
    is_active: bool = True


class PasswordChangeRequest(BaseModel):
    """Password change request model"""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


class PasswordResetRequest(BaseModel):
    """Password reset request model"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)


class UserProfile(UserResponse):
    """User profile response model"""
    role: str
    is_active: bool
    updated_at: datetime
