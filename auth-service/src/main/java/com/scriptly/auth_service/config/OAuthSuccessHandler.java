package com.scriptly.auth_service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scriptly.auth_service.dto.AuthResponse;
import com.scriptly.auth_service.entity.AuthProvider;
import com.scriptly.auth_service.entity.User;
import com.scriptly.auth_service.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthService authService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = oauthToken.getPrincipal();

        AuthProvider provider = AuthProvider.valueOf(oauthToken.getAuthorizedClientRegistrationId().toUpperCase());
        String email = resolveEmail(oauthUser, provider);
        String username = resolveUsername(oauthUser, email, provider);
        String fullName = resolveFullName(oauthUser, username);
        String avatarUrl = resolveAvatar(oauthUser, provider);

        User user = authService.processOAuthLogin(email, username, fullName, provider, avatarUrl);
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        AuthResponse authResponse = new AuthResponse(
                token,
                user.getEmail(),
                user.getRole().name(),
                user.getUsername(),
                user.isActive()
        );

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getWriter(), authResponse);
    }

    private String resolveEmail(OAuth2User oauthUser, AuthProvider provider) {
        String email = oauthUser.getAttribute("email");
        if (email != null && !email.isBlank()) {
            return email.trim().toLowerCase();
        }

        if (provider == AuthProvider.GITHUB) {
            String login = oauthUser.getAttribute("login");
            if (login != null && !login.isBlank()) {
                return login.trim().toLowerCase() + "@users.noreply.github.com";
            }
        }

        throw new IllegalStateException("OAuth provider did not return an email address");
    }

    private String resolveUsername(OAuth2User oauthUser, String email, AuthProvider provider) {
        String username = oauthUser.getAttribute("login");
        if (username == null || username.isBlank()) {
            username = oauthUser.getAttribute("name");
        }
        if (username == null || username.isBlank()) {
            username = email.contains("@") ? email.substring(0, email.indexOf('@')) : email;
        }

        String normalized = username.trim().replaceAll("\\s+", "_").toLowerCase();
        if (provider == AuthProvider.GOOGLE && normalized.length() > 40) {
            return normalized.substring(0, 40);
        }
        return normalized;
    }

    private String resolveFullName(OAuth2User oauthUser, String username) {
        String fullName = oauthUser.getAttribute("name");
        return (fullName == null || fullName.isBlank()) ? username : fullName.trim();
    }

    private String resolveAvatar(OAuth2User oauthUser, AuthProvider provider) {
        if (provider == AuthProvider.GITHUB) {
            return oauthUser.getAttribute("avatar_url");
        }
        return oauthUser.getAttribute("picture");
    }
}
