package com.caspercodes.authenticationservice.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {
    private String id;
    private String email;
    private boolean emailVerified;
    private LocalDateTime createdAt;
}
