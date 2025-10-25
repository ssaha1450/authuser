package com.careconnect.authuser.dto;

public record LogoutRequest(String accessToken, String refreshToken) {
}
