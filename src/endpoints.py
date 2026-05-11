"""
Authentication endpoints for the High School Management System
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from typing import Optional
from models import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    PasswordChangeRequest, UserProfile
)
from auth import (
    create_access_token, create_refresh_token, decode_token,
    generate_password_reset_token, verify_password
)
from database import user_db

router = APIRouter(prefix="/api/auth", tags=["authentication"])
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthCredentials = Depends(security)) -> dict:
    """
    Dependency to get the current authenticated user
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    token = credentials.credentials
    payload = decode_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    return payload


@router.post("/register", response_model=UserResponse)
def register(user_data: UserRegister):
    """
    Register a new user
    
    Args:
        user_data: User registration data
        
    Returns:
        Created user information
        
    Raises:
        HTTPException: If email already exists
    """
    try:
        user = user_db.create_user(
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            password=user_data.password
        )
        
        return UserResponse(
            user_id=user.user_id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            created_at=user.created_at,
            role=user.role
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    """
    Login a user and return access token
    
    Args:
        credentials: User login credentials
        
    Returns:
        Access token and user information
        
    Raises:
        HTTPException: If credentials are invalid
    """
    user = user_db.authenticate_user(credentials.email, credentials.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    access_token = create_access_token(user.user_id, user.email, user.role)
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            user_id=user.user_id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            created_at=user.created_at,
            role=user.role
        )
    )


@router.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """
    Logout a user (token invalidation handled by client)
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Success message
    """
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """
    Get current user's profile
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User profile information
    """
    user = user_db.get_user_by_id(current_user["user_id"])
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserProfile(
        user_id=user.user_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        created_at=user.created_at,
        updated_at=user.updated_at,
        role=user.role,
        is_active=user.is_active
    )


@router.put("/profile", response_model=UserProfile)
def update_profile(
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Update current user's profile
    
    Args:
        first_name: New first name (optional)
        last_name: New last name (optional)
        current_user: Current authenticated user
        
    Returns:
        Updated user profile
    """
    updated_user = user_db.update_user_profile(
        current_user["user_id"],
        first_name=first_name,
        last_name=last_name
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserProfile(
        user_id=updated_user.user_id,
        email=updated_user.email,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        role=updated_user.role,
        is_active=updated_user.is_active
    )


@router.post("/change-password")
def change_password(
    password_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Change current user's password
    
    Args:
        password_data: Current and new password
        current_user: Current authenticated user
        
    Returns:
        Success message
    """
    user = user_db.get_user_by_id(current_user["user_id"])
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    success = user_db.update_user_password(current_user["user_id"], password_data.new_password)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update password"
        )
    
    return {"message": "Password changed successfully"}


@router.post("/forgot-password")
def forgot_password(email: str):
    """
    Request a password reset token
    
    Args:
        email: User email
        
    Returns:
        Success message (token would be sent via email in production)
    """
    user = user_db.get_user_by_email(email)
    
    if not user:
        # Don't reveal if email exists
        return {"message": "If the email exists, a reset link will be sent"}
    
    reset_token = generate_password_reset_token(email)
    user_db.store_password_reset_token(email, reset_token)
    
    # In production, send email with reset link
    # For now, just return success
    return {"message": "Reset link sent to email (check console for token in development)"}


@router.get("/users", response_model=list[UserResponse])
def list_users(current_user: dict = Depends(get_current_user)):
    """
    List all active users (admin only in production)
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        List of active users
    """
    users = user_db.list_all_users()
    
    return [
        UserResponse(
            user_id=user.user_id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            created_at=user.created_at,
            role=user.role
        )
        for user in users
    ]


@router.get("/users/{user_id}", response_model=UserProfile)
def get_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get a specific user's profile
    
    Args:
        user_id: User ID to retrieve
        current_user: Current authenticated user
        
    Returns:
        User profile information
    """
    user = user_db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserProfile(
        user_id=user.user_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        created_at=user.created_at,
        updated_at=user.updated_at,
        role=user.role,
        is_active=user.is_active
    )
