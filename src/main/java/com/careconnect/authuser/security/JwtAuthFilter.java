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
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // ✅ Skip filtering for auth endpoints
        return path.startsWith("/api/auth/**");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String header = request.getHeader("Authorization");
        String token = null;
        String userEmail = null;

        // ✅ Extract token only if header is present
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            try {
                userEmail = jwtTokenUtil.getEmailFromToken(token);
            } catch (ExpiredJwtException ex) {
                logger.warn("JWT expired: {}", ex);
            } catch (Exception ex) {
                logger.error("Invalid JWT token: {}", ex);
            }
        }

        // ✅ Validate token and set authentication
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtTokenUtil.validateToken(token)) {
                com.careconnect.authuser.entity.User dbUser =
                        userRepository.findByEmail(userEmail).orElse(null);

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

        // ✅ This is VERY important: continue filter chain
        filterChain.doFilter(request, response);
    }
}
