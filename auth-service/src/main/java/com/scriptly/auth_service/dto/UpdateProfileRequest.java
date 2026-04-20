package com.scriptly.auth_service.dto;

import lombok.Data;

@Data
public class UpdateProfileRequest {
    private String username;
    private String fullName;
    private String bio;
    private String avatarUrl;
}
