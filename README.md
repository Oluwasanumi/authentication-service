# Authentication Service

A complete authentication service built with Spring Boot, MongoDB, Redis, and JWT tokens.

## Features

- ✅ User registration with email verification
- ✅ Login with JWT token generation
- ✅ Email verification with OTP
- ✅ Password reset functionality
- ✅ Token refresh mechanism
- ✅ Logout (single device and all devices)
- ✅ Rate limiting for OTP requests
- ✅ Secure password requirements
- ✅ Token blacklisting in Redis

## Tech Stack

- **Spring Boot** - Application framework
- **MongoDB** - User data storage
- **Redis** - Token storage and blacklisting
- **JWT** - Authentication tokens
- **Spring Security** - Security framework
- **JavaMail** - Email sending
- **BCrypt** - Password hashing

## Prerequisites

- Java 17+
- Maven 3.6+
- MongoDB 4.4+
- Redis 6.0+
- SMTP server (Gmail account for testing)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd authentication-service
```

2. Configure MongoDB:
   - Start MongoDB on localhost:27017
   - No authentication required for local development

3. Configure Redis:
   - Start Redis on localhost:6379
   - No password required for local development


## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/login` | Login user |
| POST | `/api/auth/verify-email` | Verify email with OTP |
| POST | `/api/auth/forgot-password` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with OTP |
| POST | `/api/auth/refresh-token` | Refresh access token |
| POST | `/api/auth/resend-otp` | Resend OTP |

### Protected Endpoints (Requires Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/me` | Get current user |
| POST | `/api/auth/logout` | Logout current device |
| POST | `/api/auth/logout-all` | Logout all devices |

## Request/Response Examples

### Sign Up
```json
POST /api/auth/signup
{
    "email": "user@example.com",
    "password": "Test@123456"
}

Response:
{
    "success": true,
    "message": "User registered successfully. Please check your email for verification code.",
    "data": {
        "id": "65abc123...",
        "email": "user@example.com",
        "emailVerified": false,
        "createdAt": "2024-01-01T10:00:00"
    },
    "timestamp": "2024-01-01T10:00:00"
}
```

### Login
```json
POST /api/auth/login
{
    "email": "user@example.com",
    "password": "Test@123456"
}

Response:
{
    "success": true,
    "message": "Login successful",
    "data": {
        "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
        "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
        "tokenType": "Bearer",
        "expiresIn": 3600,
        "user": {
            "id": "65abc123...",
            "email": "user@example.com",
            "emailVerified": true,
            "createdAt": "2024-01-01T10:00:00"
        }
    },
    "timestamp": "2024-01-01T10:00:00"
}
```

### Verify Email
```json
POST /api/auth/verify-email
{
    "email": "user@example.com",
    "code": "123456"
}
```

## Password Requirements

Passwords must:
- Be at least 8 characters long
- Contain at least one uppercase letter
- Contain at least one lowercase letter
- Contain at least one digit
- Contain at least one special character (@$!%*?&)

## Token Expiration

- **Access Token**: 1 hour
- **Refresh Token**: 7 days
- **OTP**: 5 minutes

## Rate Limiting

- Maximum 3 OTP requests per hour per email
- Maximum 3 failed OTP verification attempts

## Error Handling

The API returns consistent error responses:

```json
{
    "success": false,
    "message": "Error description",
    "timestamp": "2024-01-01T10:00:00"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation errors)
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict (user already exists)
- `429` - Too Many Requests
- `500` - Internal Server Error

## Security Considerations

1. **Password Storage**: Passwords are hashed using BCrypt
2. **JWT Secret**: Use a strong secret key in production
3. **HTTPS**: Always use HTTPS in production
4. **Rate Limiting**: Prevents brute force attacks
5. **Token Blacklisting**: Allows proper logout functionality
6. **Email Verification**: Ensures valid email addresses


## Troubleshooting

### Email not sending
- Check Gmail app password (not regular password)
- Enable "Less secure app access" or use App Passwords
- Check firewall settings for SMTP port 587

### MongoDB connection issues
- Ensure MongoDB is running: `mongod`
- Check connection string in application.yml
- Verify MongoDB port (default: 27017)

### Redis connection issues
- Ensure Redis is running: `redis-server`
- Check Redis port (default: 6379)
- Verify no password is set for local development

### JWT token issues
- Ensure the secret key is at least 256 bits
- Check token expiration times
- Verify token format in Authorization header: `Bearer <token>`

## Production Deployment

1. Use environment variables for sensitive data
2. Enable HTTPS
3. Use a production-grade SMTP service
4. Configure MongoDB authentication
5. Set Redis password
6. Use a reverse proxy (nginx)
7. Enable application monitoring
8. Configure proper CORS settings

