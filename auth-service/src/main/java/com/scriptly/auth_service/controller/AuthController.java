package com.scriptly.auth_service.controller;

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
import com.scriptly.auth_service.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/auth")
@CrossOrigin(
        origins = {"*"},
        allowedHeaders = "*",
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS}
)
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest req) {
        try {
            return authService.register(req);
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest req) {
        try {
            return authService.login(req);
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex);
        }
    }

    @PostMapping("/bootstrap-admin")
    public AuthResponse bootstrapAdmin(@RequestBody RegisterRequest req) {
        try {
            return authService.bootstrapAdmin(req);
        } catch (RuntimeException ex) {
            HttpStatus status = "Admin bootstrap is already completed".equals(ex.getMessage())
                    ? HttpStatus.CONFLICT
                    : HttpStatus.BAD_REQUEST;
            throw new ResponseStatusException(status, ex.getMessage(), ex);
        }
    }

    @GetMapping("/test")
    public String test() {
        return "Auth service is reachable";
    }

    @GetMapping("/validate")
    public TokenValidationResponse validateToken(@RequestHeader("Authorization") String header) {
        try {
            return authService.validateToken(extractToken(header));
        } catch (RuntimeException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex);
        }
    }

    @GetMapping("/profile")
    public ProfileResponse getProfile(@RequestHeader("Authorization") String header) {
        String token = extractToken(header);
        String email = jwtUtil.extractEmail(token);
        return authService.getProfile(email);
    }

    @PutMapping("/profile")
    public ProfileResponse updateProfile(
            @RequestHeader("Authorization") String header,
            @RequestBody UpdateProfileRequest req) {

        String token = extractToken(header);
        String email = jwtUtil.extractEmail(token);

        return authService.updateProfile(email, req);
    }

    @PutMapping("/change-password")
    public String changePassword(
            @RequestHeader("Authorization") String header,
            @RequestBody ChangePasswordRequest req) {

        String token = extractToken(header);
        String email = jwtUtil.extractEmail(token);

        return authService.changePassword(email, req);
    }

    @PutMapping("/admin/change-role")
    public String changeRole(@RequestBody ChangeRoleRequest req) {
        return authService.changeRole(req);
    }

    @GetMapping("/admin/users")
    public List<UserSummaryResponse> getAllUsers(@RequestParam(required = false) String role) {
        return role == null || role.isBlank()
                ? authService.getAllUsers()
                : authService.getUsersByRole(role);
    }

    @GetMapping("/admin/users/search")
    public List<UserSummaryResponse> searchUsers(@RequestParam(required = false) String keyword) {
        return authService.searchUsers(keyword);
    }

    @PutMapping("/admin/users/suspend")
    public String suspendUser(@RequestBody UpdateUserStatusRequest req) {
        return authService.suspendUser(req);
    }

    @PutMapping("/admin/users/reactivate")
    public String reactivateUser(@RequestBody UpdateUserStatusRequest req) {
        return authService.reactivateUser(req);
    }

    @DeleteMapping("/admin/users/{userId}")
    public String deleteUser(@PathVariable Long userId) {
        return authService.deleteUser(userId);
    }

    @GetMapping("/me")
    public ProfileResponse getMe(@RequestHeader("Authorization") String header) {
        String token = extractToken(header);
        String email = jwtUtil.extractEmail(token);
        return authService.getProfile(email);
    }

    @PutMapping("/deactivate")
    public String deactivate(@RequestHeader("Authorization") String header) {
        String token = extractToken(header);
        String email = jwtUtil.extractEmail(token);

        return authService.deactivateAccount(email);
    }

    @GetMapping("/access/reader")
    public String readerAccess() {
        return "Reader access granted";
    }

    @GetMapping("/access/author")
    public String authorAccess() {
        return "Author access granted";
    }

    @GetMapping("/access/admin")
    public String adminAccess() {
        return "Admin access granted";
    }

    private String extractToken(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing bearer token");
        }
        return header.substring(7);
    }

    @GetMapping("/oauth-success")
    public String success(@RequestParam String token, @RequestParam String email) {
        return "OAuth Success! token=" + token + " email=" + email;
    }
}
