package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class UserNotFoundException extends AuthenticationException {
    public UserNotFoundException(String email) {
        super("User with email " + email + " not found");
    }
}
