package com.scriptly.auth_service.entity;

public enum Role {
    READER,
    AUTHOR,
    ADMIN;

    public static Role from(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Role is required");
        }

        try {
            return Role.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported role: " + value);
        }
    }
}
