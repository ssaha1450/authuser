package com.careconnect.authuser.service;

import com.careconnect.authuser.dto.*;
import com.careconnect.authuser.entity.TokenType;
import com.careconnect.authuser.entity.User;
import com.careconnect.authuser.entity.UserToken;
import com.careconnect.authuser.repository.UserRepository;
import com.careconnect.authuser.repository.UserTokenRepository;
import com.careconnect.authuser.security.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
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
            throw new RuntimeException("Email already registered");

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

        if (!passwordEncoder.matches(loginRequest.password(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

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
            throw new RuntimeException("Invalid or revoked refresh token");

        if (token.getExpiresAt().isBefore(LocalDateTime.now()))
            throw new RuntimeException("Refresh token has expired, please log in again");

        if (!jwtTokenUtil.validateToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        String email = jwtTokenUtil.getEmailFromToken(refreshToken);
        String newAccessToken = jwtTokenUtil.generateAccessToken(email);
        userTokenRepository.save(UserToken.builder()
                .user(userRepository.findByEmail(email).get())
                .token(newAccessToken)
                .tokenType(TokenType.ACCESS_TOKEN)
                .invalidated(false)
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .build());
        return new AuthResponse(newAccessToken, refreshToken);
    }

    @Transactional
    public void logout(String accessToken) {
        userTokenRepository.findByToken(accessToken).ifPresent(at -> {
            at.setInvalidated(true);
            userTokenRepository.save(at);

            // Invalidate corresponding refresh token for the same user
            userTokenRepository.findByUserIdAndTokenTypeAndInvalidatedFalse(at.getUser().getId(), TokenType.REFRESH_TOKEN)
                    .ifPresent(rt -> {
                        rt.setInvalidated(true);
                        userTokenRepository.save(rt);
                    });
        });

    }
}
//    @Transactional
//    public void logout(BlacklistedToken blacklistedToken) {
//        // 1️⃣ Revoke refresh token
//        refreshTokenRepository.findByToken(refreshToken).ifPresent(rt -> {
//            rt.setRevoked(true);
//            refreshTokenRepository.save(rt);
//        });
//
//        // 2️⃣ Blacklist access token
//        if (accessToken != null && jwtTokenUtil.validateToken(accessToken)) {
//            BlacklistedToken blacklisted = BlacklistedToken.builder()
//                    .token(accessToken)
//                    .expiryDate(Instant.ofEpochMilli(jwtTokenUtil.getExpiryDateFromToken(accessToken).getTime()))
//                    .build();
//            blacklistedTokenRepository.save(blacklisted);
//        }


