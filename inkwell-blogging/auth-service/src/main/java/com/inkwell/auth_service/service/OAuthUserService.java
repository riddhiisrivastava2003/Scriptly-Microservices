package com.inkwell.auth_service.service;

import com.inkwell.auth_service.model.AuthProvider;
import com.inkwell.auth_service.model.User;
import com.inkwell.auth_service.model.UserRole;
import com.inkwell.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OAuthUserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauthUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attrs = oauthUser.getAttributes();

        String email = (String) attrs.get("email");
        if (email == null || email.isBlank()) {
            email = registrationId + "_" + UUID.randomUUID() + "@oauth.local";
        }

        String name = (String) attrs.getOrDefault("name", email.split("@")[0]);

        User user = userRepository.findByEmail(email).orElseGet(User::new);
        user.setEmail(email);
        user.setFullName(name);
        user.setUsername(email.split("@")[0]);
        user.setRole(user.getRole() == null ? UserRole.READER : user.getRole());
        user.setProvider("github".equalsIgnoreCase(registrationId) ? AuthProvider.GITHUB : AuthProvider.GOOGLE);
        user.setActive(true);

        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
            user.setPasswordHash(UUID.randomUUID().toString());
        }

        userRepository.save(user);
        return oauthUser;
    }
}
