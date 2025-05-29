package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Base exception class for authentication service
 */
public class AuthenticationException extends RuntimeException {
    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}

/**
 * Thrown when credentials are invalid
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidCredentialsException extends AuthenticationException {
    public InvalidCredentialsException() {
        super("Invalid email or password");
    }
}

/**
 * Thrown when OTP is invalid or expired
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidOtpException extends AuthenticationException {
    public InvalidOtpException() {
        super("Invalid or expired OTP");
    }
}

/**
 * Thrown when email is not verified
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class EmailNotVerifiedException extends AuthenticationException {
    public EmailNotVerifiedException() {
        super("Email not verified. Please verify your email first");
    }
}

/**
 * Thrown when JWT token is invalid
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String message) {
        super(message);
    }
}

/**
 * Thrown when rate limit is exceeded
 */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class RateLimitExceededException extends AuthenticationException {
    public RateLimitExceededException(String message) {
        super(message);
    }
}