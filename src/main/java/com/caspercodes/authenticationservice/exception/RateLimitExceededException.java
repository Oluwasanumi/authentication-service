package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class RateLimitExceededException extends AuthenticationException {
    public RateLimitExceededException(String message) {
        super(message);
    }
}
