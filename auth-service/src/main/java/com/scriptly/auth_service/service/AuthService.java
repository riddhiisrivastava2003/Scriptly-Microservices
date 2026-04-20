package com.scriptly.auth_service.service;

import com.scriptly.auth_service.config.JwtUtil;
import com.scriptly.auth_service.dto.AuthResponse;
import com.scriptly.auth_service.dto.ChangePasswordRequest;
import com.scriptly.auth_service.dto.ChangeRoleRequest;
import com.scriptly.auth_service.dto.LoginRequest;
import com.scriptly.auth_service.dto.ProfileResponse;
import com.scriptly.auth_service.dto.RegisterRequest;
import com.scriptly.auth_service.dto.TokenValidationResponse;
import com.scriptly.auth_service.dto.UpdateProfileRequest;
import com.scriptly.auth_service.dto.UpdateUserStatusRequest;
import com.scriptly.auth_service.dto.UserSummaryResponse;
import com.scriptly.auth_service.entity.AuthProvider;
import com.scriptly.auth_service.entity.Role;
import com.scriptly.auth_service.entity.User;
import com.scriptly.auth_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthResponse register(RegisterRequest req) {
        validateRegistrationRequest(req);

        if (userRepository.existsByEmail(req.getEmail())) {
            throw new RuntimeException("User already exists with this email");
        }
        if (userRepository.existsByUsername(req.getUsername())) {
            throw new RuntimeException("Username is already taken");
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setFullName(req.getFullName());
        user.setEmail(req.getEmail());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setRole(Role.READER);
        user.setProvider(AuthProvider.LOCAL);
        user.setActive(true);

        User savedUser = userRepository.save(user);
        String token = jwtUtil.generateToken(savedUser.getEmail(), savedUser.getRole().name());

        return new AuthResponse(
                token,
                savedUser.getEmail(),
                savedUser.getRole().name(),
                savedUser.getUsername(),
                savedUser.isActive()
        );
    }

    public AuthResponse bootstrapAdmin(RegisterRequest req) {
        if (userRepository.countByRole(Role.ADMIN) > 0) {
            throw new RuntimeException("Admin bootstrap is already completed");
        }

        validateRegistrationRequest(req);
        if (userRepository.existsByEmail(req.getEmail())) {
            throw new RuntimeException("User already exists with this email");
        }
        if (userRepository.existsByUsername(req.getUsername())) {
            throw new RuntimeException("Username is already taken");
        }

        User user = new User();
        user.setUsername(req.getUsername().trim());
        user.setFullName(req.getFullName());
        user.setEmail(req.getEmail().trim().toLowerCase());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setRole(Role.ADMIN);
        user.setProvider(AuthProvider.LOCAL);
        user.setActive(true);

        User savedUser = userRepository.save(user);
        String token = jwtUtil.generateToken(savedUser.getEmail(), savedUser.getRole().name());
        return new AuthResponse(token, savedUser.getEmail(), savedUser.getRole().name(), savedUser.getUsername(), savedUser.isActive());
    }

    public AuthResponse login(LoginRequest req) {
        if (req.getEmail() == null || req.getEmail().isBlank() || req.getPassword() == null || req.getPassword().isBlank()) {
            throw new RuntimeException("Email and password are required");
        }

        User user = userRepository.findByEmail(req.getEmail().trim().toLowerCase())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        if (!user.isActive()) {
            throw new RuntimeException("Account is deactivated");
        }

        if (user.getProvider() != AuthProvider.LOCAL || user.getPassword() == null || user.getPassword().isBlank()) {
            throw new RuntimeException("This account uses " + user.getProvider().name().toLowerCase() + " sign-in. Please continue with OAuth.");
        }

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, user.getEmail(), user.getRole().name(), user.getUsername(), user.isActive());
    }

    public User processOAuthLogin(String email, String username, String fullName, AuthProvider provider, String avatarUrl) {
        String normalizedEmail = email.trim().toLowerCase();
        User user = userRepository.findByEmail(normalizedEmail).orElseGet(User::new);

        if (user.getUserId() == null) {
            user.setEmail(normalizedEmail);
            user.setRole(Role.READER);
            user.setActive(true);
        }

        user.setUsername(resolveUniqueUsername(username, user.getUserId()));
        user.setFullName(fullName == null ? null : fullName.trim());
        user.setProvider(provider);
        user.setAvatarUrl(avatarUrl);

        return userRepository.save(user);
    }

    public ProfileResponse getProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return mapToProfile(user);
    }

    public ProfileResponse updateProfile(String email, UpdateProfileRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (req.getUsername() != null && !req.getUsername().isBlank() && !req.getUsername().equalsIgnoreCase(user.getUsername())) {
            if (userRepository.existsByUsername(req.getUsername())) {
                throw new RuntimeException("Username is already taken");
            }
            user.setUsername(req.getUsername().trim());
        }
        if (req.getFullName() != null) {
            user.setFullName(req.getFullName().trim());
        }
        user.setBio(req.getBio());
        user.setAvatarUrl(req.getAvatarUrl());

        userRepository.save(user);
        return getProfile(email);
    }

    public String changePassword(String email, ChangePasswordRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(req.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Old password incorrect");
        }

        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(user);

        return "Password updated successfully";
    }

    public String changeRole(ChangeRoleRequest req) {
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setRole(Role.from(req.getRole()));
        userRepository.save(user);

        return "Role updated to " + req.getRole();
    }

    public List<UserSummaryResponse> getAllUsers() {
        return userRepository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::mapToSummary)
                .toList();
    }

    public List<UserSummaryResponse> getUsersByRole(String role) {
        return userRepository.findAllByRole(Role.from(role)).stream()
                .map(this::mapToSummary)
                .toList();
    }

    public List<UserSummaryResponse> searchUsers(String keyword) {
        String value = keyword == null ? "" : keyword.trim();
        if (value.isEmpty()) {
            return getAllUsers();
        }
        return userRepository.searchByKeyword(value).stream()
                .map(this::mapToSummary)
                .toList();
    }

    public String suspendUser(UpdateUserStatusRequest req) {
        User user = findUserByEmail(req.getEmail());
        user.setActive(false);
        userRepository.save(user);
        return "User suspended successfully";
    }

    public String reactivateUser(UpdateUserStatusRequest req) {
        User user = findUserByEmail(req.getEmail());
        user.setActive(true);
        userRepository.save(user);
        return "User reactivated successfully";
    }

    public String deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepository.delete(user);
        return "User deleted successfully";
    }

    public String deactivateAccount(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setActive(false);
        userRepository.save(user);

        return "Account deactivated";
    }

    public TokenValidationResponse validateToken(String token) {
        if (!jwtUtil.isTokenValid(token)) {
            throw new RuntimeException("Invalid or expired token");
        }

        String email = jwtUtil.extractEmail(token);
        User user = findUserByEmail(email);
        return new TokenValidationResponse(true, user.getEmail(), user.getRole().name(), user.isActive());
    }

    private void validateRegistrationRequest(RegisterRequest req) {
        if (req.getUsername() == null || req.getUsername().isBlank()) {
            throw new RuntimeException("Username is required");
        }
        if (req.getEmail() == null || req.getEmail().isBlank()) {
            throw new RuntimeException("Email is required");
        }
        if (req.getPassword() == null || req.getPassword().length() < 8) {
            throw new RuntimeException("Password must be at least 8 characters");
        }
        req.setUsername(req.getUsername().trim());
        req.setEmail(req.getEmail().trim().toLowerCase());
        if (req.getFullName() != null) {
            req.setFullName(req.getFullName().trim());
        }
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    private ProfileResponse mapToProfile(User user) {
        return new ProfileResponse(
                user.getUsername(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().name(),
                user.getProvider().name(),
                user.getBio(),
                user.getAvatarUrl(),
                user.isActive()
        );
    }

    private UserSummaryResponse mapToSummary(User user) {
        return new UserSummaryResponse(
                user.getUserId(),
                user.getUsername(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().name(),
                user.getProvider().name(),
                user.isActive(),
                user.getCreatedAt()
        );
    }

    private String resolveUniqueUsername(String baseUsername, Long currentUserId) {
        String normalized = (baseUsername == null || baseUsername.isBlank() ? "user" : baseUsername.trim())
                .replaceAll("\\s+", "_")
                .toLowerCase();

        String candidate = normalized;
        int suffix = 1;

        while (true) {
            User existingUser = userRepository.findByUsername(candidate).orElse(null);
            if (existingUser == null || existingUser.getUserId().equals(currentUserId)) {
                return candidate;
            }
            candidate = normalized + suffix++;
        }
    }
}
