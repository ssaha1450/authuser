package com.careconnect.authuser.dto;

import com.careconnect.authuser.entity.Role;
import lombok.Data;

@Data
public class RegisterRequest {
    private String email;
    private String password;
    private String fullName;
    private Role role;
}