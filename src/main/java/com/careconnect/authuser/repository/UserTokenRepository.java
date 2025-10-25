package com.careconnect.authuser.repository;

import com.careconnect.authuser.entity.UserToken;
import com.careconnect.authuser.entity.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserTokenRepository extends JpaRepository<UserToken, Long> {

    Optional<UserToken> findByToken(String token);

    List<UserToken> findAllByUserIdAndInvalidatedFalse(Long userId);

    Optional<List<UserToken>> findByUserIdAndTokenTypeAndInvalidatedFalse(Long userId, TokenType tokenType);
}
