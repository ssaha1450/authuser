package com.careconnect.authuser.service;

import com.careconnect.authuser.dto.*;
import com.careconnect.authuser.entity.TokenType;
import com.careconnect.authuser.entity.User;
import com.careconnect.authuser.entity.UserToken;
import com.careconnect.authuser.repository.UserRepository;
import com.careconnect.authuser.repository.UserTokenRepository;
import com.careconnect.authuser.security.JwtTokenUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.persistence.EntityExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserTokenRepository userTokenRepository;

    public void register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail()))
            throw new EntityExistsException("Email already registered");

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .role(request.getRole())
                .build();

        userRepository.save(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password())
        );

        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new RuntimeException("User not found"));


        String accessToken = jwtTokenUtil.generateAccessToken(user.getEmail());
        String refreshToken = jwtTokenUtil.generateRefreshToken(user.getEmail());

        // Save access token (valid for 15 mins)
        userTokenRepository.save(UserToken.builder()
                .user(user)
                .token(accessToken)
                .tokenType(TokenType.ACCESS_TOKEN)
                .invalidated(false)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .build());

        // Save refresh token (valid for 7 days)
        userTokenRepository.save(UserToken.builder()
                .user(user)
                .token(refreshToken)
                .tokenType(TokenType.REFRESH_TOKEN)
                .invalidated(false)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build());

        return new AuthResponse(accessToken, refreshToken);
    }

    // Refresh token method
    @Transactional
    public AuthResponse refreshAccessToken(String refreshToken) {
        UserToken token = userTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (token.isInvalidated() || token.getTokenType() != TokenType.REFRESH_TOKEN)
            throw new InvalidOneTimeTokenException("Invalid or revoked refresh token");

        if (token.getExpiresAt().isBefore(LocalDateTime.now()))
            throw new ExpiredJwtException(null, null, "Refresh Token expired");

        if (!jwtTokenUtil.validateToken(refreshToken)) {
            throw new InvalidOneTimeTokenException("Expired refresh token");
        }

        String email = jwtTokenUtil.getEmailFromToken(refreshToken);
        String newAccessToken = jwtTokenUtil.generateAccessToken(email);
        User user= userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userTokenRepository.save(UserToken.builder()
                .user(user)
                .token(newAccessToken)
                .tokenType(TokenType.ACCESS_TOKEN)
                .invalidated(false)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .build());
        return new AuthResponse(newAccessToken, refreshToken);
    }

    @Transactional
    public void logout(String accessToken) {
        userTokenRepository.findByToken(accessToken).ifPresent(userAccessToken -> {
            // Invalidate access token
            userAccessToken.setInvalidated(true);
            userTokenRepository.save(userAccessToken);

            // Invalidate refresh tokens for same user
            userTokenRepository.findByUserIdAndTokenTypeAndInvalidatedFalse(
                    userAccessToken.getUser().getId(),
                    TokenType.REFRESH_TOKEN
            ).ifPresent(refreshTokens -> {
                refreshTokens.forEach(refreshToken -> {
                    refreshToken.setInvalidated(true);
                    userTokenRepository.save(refreshToken);
                });
            });
        });
    }
}
