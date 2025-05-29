package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus; /**
 * Thrown when user already exists
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class UserAlreadyExistsException extends AuthenticationException {
    public UserAlreadyExistsException(String email) {
        super("User with email " + email + " already exists");
    }
}
