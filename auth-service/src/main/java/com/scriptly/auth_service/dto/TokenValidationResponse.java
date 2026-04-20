package com.scriptly.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenValidationResponse {
    private boolean valid;
    private String email;
    private String role;
    private boolean active;
}
