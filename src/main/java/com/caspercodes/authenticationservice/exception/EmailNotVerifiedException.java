package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(HttpStatus.FORBIDDEN)
public class EmailNotVerifiedException extends AuthenticationException {
    public EmailNotVerifiedException() {
        super("Email not verified. Please verify your email first");
    }
}
