package com.caspercodes.authenticationservice.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class OtpGenerator {

    @Value("${app.otp.length}")
    private int otpLength;

    private static final String DIGITS = "0123456789";
    private final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        StringBuilder otp = new StringBuilder(otpLength);

        for (int i = 0; i < otpLength; i++) {
            otp.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        }

        return otp.toString();
    }

    public String generateOtp(int length) {
        StringBuilder otp = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            otp.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        }

        return otp.toString();
    }
}