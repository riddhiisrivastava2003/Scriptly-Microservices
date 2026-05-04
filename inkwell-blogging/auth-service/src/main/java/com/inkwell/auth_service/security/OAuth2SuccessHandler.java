package com.inkwell.auth_service.security;

import com.inkwell.auth_service.model.User;
import com.inkwell.auth_service.repository.UserRepository;
import com.inkwell.auth_service.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${app.frontend-base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (!(authentication.getPrincipal() instanceof OAuth2User oauth2User)) {
            response.sendRedirect(frontendBaseUrl + "/login");
            return;
        }

        String email = String.valueOf(oauth2User.getAttributes().getOrDefault("email", ""));
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            response.sendRedirect(frontendBaseUrl + "/login");
            return;
        }

        String token = jwtService.generateToken(user.getId(), user.getEmail(), user.getRole().name());
        String redirect = frontendBaseUrl + "/auth/oauth-success?token="
                + URLEncoder.encode(token, StandardCharsets.UTF_8)
                + "&userId=" + user.getId()
                + "&email=" + URLEncoder.encode(user.getEmail(), StandardCharsets.UTF_8)
                + "&username=" + URLEncoder.encode(user.getUsername(), StandardCharsets.UTF_8)
                + "&role=" + user.getRole().name();
        response.sendRedirect(redirect);
    }
}
