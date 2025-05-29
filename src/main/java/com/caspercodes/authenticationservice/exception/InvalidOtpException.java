package com.caspercodes.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus; /**
 * Thrown when OTP is invalid or expired
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidOtpException extends AuthenticationException {
    public InvalidOtpException() {
        super("Invalid or expired OTP");
    }
}
