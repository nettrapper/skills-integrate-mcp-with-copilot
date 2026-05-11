# User Management & JWT Authentication Implementation

## Overview
This implementation adds comprehensive user management and JWT-based authentication to the Mergington High School Management System.

## Files Created

### 1. `models.py` - Pydantic Data Models
Contains all request/response models for user operations:
- `UserRegister` - Registration request model
- `UserLogin` - Login credentials model
- `UserResponse` - User information response
- `TokenResponse` - Authentication token response
- `User` - Internal user database model
- `PasswordChangeRequest` - Password change request
- `PasswordResetRequest` - Password reset request
- `UserProfile` - Full user profile response

### 2. `auth.py` - Authentication Utilities
Provides core security functions:
- `hash_password()` - Securely hash passwords using bcrypt
- `verify_password()` - Verify plain password against hash
- `create_access_token()` - Generate JWT access tokens (60 min expiry)
- `create_refresh_token()` - Generate JWT refresh tokens (7 day expiry)
- `decode_token()` - Decode and validate JWT tokens
- `generate_password_reset_token()` - Create secure reset tokens
- `generate_email_verification_token()` - Create verification tokens

### 3. `database.py` - User Database
In-memory user database with persistence hooks:
- `UserDatabase` class manages all user operations
- `create_user()` - Register new users
- `get_user_by_id()` - Retrieve user by ID
- `get_user_by_email()` - Retrieve user by email
- `authenticate_user()` - Validate login credentials
- `update_user_password()` - Change user password
- `update_user_profile()` - Update user info
- `deactivate_user()` / `activate_user()` - Account status management
- Token storage for password reset and email verification flows

### 4. `endpoints.py` - API Routes
Complete authentication API endpoints:

#### Public Endpoints
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get access token
- `POST /api/auth/forgot-password` - Request password reset

#### Protected Endpoints (Require Bearer Token)
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user profile
- `PUT /api/auth/profile` - Update profile
- `POST /api/auth/change-password` - Change password
- `GET /api/auth/users` - List all users
- `GET /api/auth/users/{user_id}` - Get specific user

## Updated Files

### `app.py` - Main Application
- Added CORS middleware for frontend integration
- Imported and included authentication router
- Updated description to reflect authentication features

### `requirements.txt` - Dependencies
Added new packages:
- `pyjwt>=2.8.0` - JWT token handling
- `passlib[bcrypt]>=1.7.4` - Password hashing
- `python-multipart>=0.0.5` - Form data parsing
- `pydantic>=2.0.0` - Data validation
- `email-validator>=2.0.0` - Email validation

## Key Features Implemented

### 1. User Registration
- Email validation
- Password strength requirements (min 8 chars)
- Duplicate email prevention
- User ID generation (UUID)
- Role-based user types (student, admin, staff)

### 2. Authentication
- JWT-based token system
- Bearer token validation
- Automatic token expiration (60 minutes)
- Role-based access control ready
- Secure password hashing with bcrypt

### 3. Password Management
- Secure password hashing
- Password change endpoint
- Password reset token generation
- Current password verification for changes

### 4. User Profile Management
- Get current user profile
- Update user name and info
- Account activation/deactivation
- User listing for admins

### 5. Security Features
- CORS support for frontend
- HTTP Bearer authentication
- Token payload validation
- Expired token handling
- Role-based authorization hooks

## Environment Variables

Set in production:
```
SECRET_KEY=your-very-secure-secret-key-here
```

Default development value: `your-secret-key-change-in-production-12345`

## Usage Examples

### Register a User
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "student@school.edu",
    "first_name": "John",
    "last_name": "Doe",
    "password": "SecurePassword123"
  }'
```

### Login
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "student@school.edu",
    "password": "SecurePassword123"
  }'
```

### Access Protected Endpoint
```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```

## Architecture Notes

- **In-Memory Storage**: Currently uses in-memory database for development
- **Production Ready**: Hooks for adding database persistence (PostgreSQL, MongoDB, etc.)
- **Extensible**: Role-based access control can be implemented in endpoints
- **Token-Based**: Stateless JWT authentication allows horizontal scaling
- **Secure Defaults**: Bcrypt for password hashing, JWT signatures for token validation

## Next Steps

1. Add database persistence layer (SQLAlchemy, etc.)
2. Implement email verification for registration
3. Implement password reset email flow
4. Add role-based authorization decorators
5. Integrate with activities management
6. Add user refresh token rotation
7. Implement two-factor authentication (optional)

## Testing

The authentication system is ready to test immediately. All endpoints are accessible via the FastAPI interactive docs at:
```
http://localhost:8000/docs
```
