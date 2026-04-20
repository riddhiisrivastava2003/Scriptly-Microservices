package com.scriptly.auth_service.dto;

import lombok.Data;

@Data
public class ChangeRoleRequest {
    private String email;
    private String role;
}
