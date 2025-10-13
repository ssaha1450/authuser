package com.careconnect.authuser.security;

import com.careconnect.authuser.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String header = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // ✅ Extract token from "Authorization: Bearer <token>"
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(token);
            } catch (ExpiredJwtException ex) {
                logger.warn("JWT expired: {}", ex);
            } catch (Exception ex) {
                logger.error("Invalid JWT token: {}", ex);
            }
        }

        // ✅ Validate token and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtTokenUtil.validateJwtToken(token)) {
                com.careconnect.authuser.entity.User dbUser =
                        userRepository.findByEmail(username).orElse(null);

                if (dbUser != null && dbUser.isActive()) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    new User(dbUser.getEmail(), dbUser.getPassword(), Collections.emptyList()),
                                    null,
                                    Collections.emptyList()
                            );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
