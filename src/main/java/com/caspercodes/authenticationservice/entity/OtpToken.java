package com.caspercodes.authenticationservice.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;


@Document(collection = "otp_tokens")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpToken {

    @Id
    private String id;


    @Indexed
    private String email;


    private String code;


    private OtpType type;


    private LocalDateTime createdAt;


    @Indexed
    private LocalDateTime expiresAt;


    private boolean used;


    private int attempts;


    public enum OtpType {
        EMAIL_VERIFICATION,
        PASSWORD_RESET
    }
}