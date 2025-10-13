package com.careconnect.authuser.entity;

import com.careconnect.authuser.entity.TokenType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 512, unique = true)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType; // ACCESS or REFRESH

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private com.careconnect.authuser.entity.User user;

    @Column(nullable = false)
    private boolean invalidated = false;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;
}
