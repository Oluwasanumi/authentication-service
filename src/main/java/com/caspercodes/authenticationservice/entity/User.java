package com.caspercodes.authenticationservice.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    private String id;


    @Indexed(unique = true)
    private String email;


    private String password;


    private boolean emailVerified;


    private boolean enabled;


    @CreatedDate
    private LocalDateTime createdAt;


    @LastModifiedDate
    private LocalDateTime updatedAt;


    private int failedLoginAttempts;
    private LocalDateTime lastLoginAt;
    private LocalDateTime lastPasswordResetAt;
}