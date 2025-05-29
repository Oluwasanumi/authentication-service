package com.caspercodes.authenticationservice.repository;

import com.caspercodes.authenticationservice.entity.OtpToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;


@Repository
public interface OtpTokenRepository extends MongoRepository<OtpToken, String> {

    Optional<OtpToken> findFirstByEmailAndTypeAndUsedFalseOrderByCreatedAtDesc(String email, OtpToken.OtpType type);

    @Query("{'email': ?0, 'code': ?1, 'type': ?2, 'used': false, 'expiresAt': {$gt: ?3}}")
    Optional<OtpToken> findValidOtp(String email, String code, OtpToken.OtpType type, LocalDateTime now);

    void deleteAllByEmail(String email);

    long countByEmailAndTypeAndUsedFalseAndCreatedAtAfter(String email, OtpToken.OtpType type, LocalDateTime after);
}