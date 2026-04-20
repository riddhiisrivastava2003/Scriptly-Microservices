package com.scriptly.auth_service.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProfileResponse {
    private String username;
    private String fullName;
    private String email;
    private String role;
    private String provider;
    private String bio;
    private String avatarUrl;
    private boolean active;
}
