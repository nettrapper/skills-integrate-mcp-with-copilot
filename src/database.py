"""
User database management for the High School Management System
"""

from datetime import datetime, timedelta
from typing import Optional, Dict
import uuid
from models import User
from auth import hash_password, verify_password


class UserDatabase:
    """In-memory user database with file persistence support"""
    
    def __init__(self):
        """Initialize the user database"""
        self.users: Dict[str, User] = {}
        self.email_index: Dict[str, str] = {}  # Maps email to user_id for quick lookup
        self.password_reset_tokens: Dict[str, tuple] = {}  # token -> (user_id, expiry)
        self.email_verification_tokens: Dict[str, tuple] = {}  # token -> (email, expiry)
    
    def create_user(self, email: str, first_name: str, last_name: str, password: str, role: str = "student") -> User:
        """
        Create a new user
        
        Args:
            email: User email
            first_name: User's first name
            last_name: User's last name
            password: Plain text password
            role: User role (default: student)
            
        Returns:
            Created User object
            
        Raises:
            ValueError: If email already exists
        """
        if email in self.email_index:
            raise ValueError(f"User with email {email} already exists")
        
        user_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        user = User(
            user_id=user_id,
            email=email,
            first_name=first_name,
            last_name=last_name,
            hashed_password=hash_password(password),
            created_at=now,
            updated_at=now,
            role=role,
            is_active=True
        )
        
        self.users[user_id] = user
        self.email_index[email] = user_id
        
        return user
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Get a user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User object or None if not found
        """
        return self.users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email
        
        Args:
            email: User email
            
        Returns:
            User object or None if not found
        """
        user_id = self.email_index.get(email)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with email and password
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        user = self.get_user_by_email(email)
        
        if not user:
            return None
        
        if not user.is_active:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        return user
    
    def update_user_password(self, user_id: str, new_password: str) -> bool:
        """
        Update a user's password
        
        Args:
            user_id: User ID
            new_password: New plain text password
            
        Returns:
            True if successful, False if user not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        user.hashed_password = hash_password(new_password)
        user.updated_at = datetime.utcnow()
        self.users[user_id] = user
        
        return True
    
    def update_user_profile(self, user_id: str, first_name: Optional[str] = None, 
                           last_name: Optional[str] = None) -> Optional[User]:
        """
        Update user profile information
        
        Args:
            user_id: User ID
            first_name: New first name (optional)
            last_name: New last name (optional)
            
        Returns:
            Updated User object or None if not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return None
        
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        
        user.updated_at = datetime.utcnow()
        self.users[user_id] = user
        
        return user
    
    def deactivate_user(self, user_id: str) -> bool:
        """
        Deactivate a user account
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False if user not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        user.is_active = False
        user.updated_at = datetime.utcnow()
        self.users[user_id] = user
        
        return True
    
    def activate_user(self, user_id: str) -> bool:
        """
        Activate a user account
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False if user not found
        """
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        user.is_active = True
        user.updated_at = datetime.utcnow()
        self.users[user_id] = user
        
        return True
    
    def list_all_users(self) -> list:
        """
        Get all active users
        
        Returns:
            List of User objects
        """
        return [user for user in self.users.values() if user.is_active]
    
    def store_password_reset_token(self, email: str, token: str) -> bool:
        """
        Store a password reset token
        
        Args:
            email: User email
            token: Reset token
            
        Returns:
            True if successful, False if user not found
        """
        user = self.get_user_by_email(email)
        if not user:
            return False
        
        expiry = datetime.utcnow() + timedelta(hours=1)
        self.password_reset_tokens[token] = (user.user_id, expiry)
        
        return True
    
    def verify_password_reset_token(self, token: str) -> Optional[str]:
        """
        Verify a password reset token
        
        Args:
            token: Reset token
            
        Returns:
            User ID if valid, None if invalid or expired
        """
        if token not in self.password_reset_tokens:
            return None
        
        user_id, expiry = self.password_reset_tokens[token]
        
        if datetime.utcnow() > expiry:
            del self.password_reset_tokens[token]
            return None
        
        return user_id


# Global user database instance
user_db = UserDatabase()
