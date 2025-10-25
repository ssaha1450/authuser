package com.careconnect.authuser.entity;

import jakarta.persistence.*;
import lombok.*;


@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, unique=true)
    private String email;

    @Column(nullable=false)
    private String password;

    private String fullName;

    @Enumerated(EnumType.STRING)
    private Role role;

    private boolean active = true;
}
