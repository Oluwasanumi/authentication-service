package com.caspercodes.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Service for managing tokens in Redis.
 *
 * Token storage strategy:
 * - Access tokens: Stored with key "access:userId:tokenId"
 * - Refresh tokens: Stored with key "refresh:userId:tokenId"
 * - Blacklisted tokens: Stored with key "blacklist:token"
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${app.jwt.expiration}")
    private Long accessTokenExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private Long refreshTokenExpiration;

    // Key prefixes
    private static final String ACCESS_TOKEN_PREFIX = "access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";
    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final String USER_TOKENS_PREFIX = "user_tokens:";

    /**
     * Store access token in Redis
     */
    public void storeAccessToken(String userId, String token, String tokenId) {
        String key = ACCESS_TOKEN_PREFIX + userId + ":" + tokenId;
        redisTemplate.opsForValue().set(key, token, accessTokenExpiration, TimeUnit.MILLISECONDS);

        // Also store in user's token set for easy retrieval
        String userTokensKey = USER_TOKENS_PREFIX + userId;
        redisTemplate.opsForSet().add(userTokensKey, key);
        redisTemplate.expire(userTokensKey, refreshTokenExpiration, TimeUnit.MILLISECONDS);

        log.debug("Stored access token for user: {}", userId);
    }

    /**
     * Store refresh token in Redis
     */
    public void storeRefreshToken(String userId, String token, String tokenId) {
        String key = REFRESH_TOKEN_PREFIX + userId + ":" + tokenId;
        redisTemplate.opsForValue().set(key, token, refreshTokenExpiration, TimeUnit.MILLISECONDS);

        // Also store in user's token set
        String userTokensKey = USER_TOKENS_PREFIX + userId;
        redisTemplate.opsForSet().add(userTokensKey, key);

        log.debug("Stored refresh token for user: {}", userId);
    }

    /**
     * Check if token exists in Redis (not blacklisted)
     */
    public boolean isTokenValid(String token) {
        String blacklistKey = BLACKLIST_PREFIX + token;
        return !Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    /**
     * Blacklist a token (for logout)
     */
    public void blacklistToken(String token, long expirationTime) {
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(key, true, expirationTime, TimeUnit.MILLISECONDS);
        log.debug("Blacklisted token: {}", token.substring(0, 20) + "...");
    }

    /**
     * Remove all tokens for a user (for logout all devices)
     */
    public void removeAllUserTokens(String userId) {
        String userTokensKey = USER_TOKENS_PREFIX + userId;
        var tokenKeys = redisTemplate.opsForSet().members(userTokensKey);

        if (tokenKeys != null && !tokenKeys.isEmpty()) {
            // Delete all token keys
            tokenKeys.forEach(key -> redisTemplate.delete(String.valueOf(key)));
            // Delete the set itself
            redisTemplate.delete(userTokensKey);
            log.debug("Removed all tokens for user: {}", userId);
        }
    }

    /**
     * Get token by key pattern
     */
    public String getToken(String key) {
        Object value = redisTemplate.opsForValue().get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Check if user has active sessions
     */
    public boolean hasActiveTokens(String userId) {
        String userTokensKey = USER_TOKENS_PREFIX + userId;
        Long size = redisTemplate.opsForSet().size(userTokensKey);
        return size != null && size > 0;
    }
}