package com.caspercodes.authenticationservice.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {
    private boolean valid;
    private String email;
    private String userId;
}