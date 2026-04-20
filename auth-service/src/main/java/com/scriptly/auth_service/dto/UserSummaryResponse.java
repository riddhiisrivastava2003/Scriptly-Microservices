package com.scriptly.auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSummaryResponse {
    private Long userId;
    private String username;
    private String fullName;
    private String email;
    private String role;
    private String provider;
    private boolean active;
    private Instant createdAt;
}
