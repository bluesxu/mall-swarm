package com.macro.mall.common.util;

import com.macro.mall.common.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * JWT令牌工具类
 */
@Component
public class JwtTokenProvider {

    private final JwtProperties jwtProperties;
    private final SecretKey secretKey;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.secretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 生成JWT令牌
     *
     * @param userId      用户ID
     * @param username    用户名
     * @param userType    用户类型（admin/member）
     * @param permissions 权限列表（member可为null）
     * @return JWT令牌
     */
    public String generateToken(Long userId, String username, String userType, List<String> permissions) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + jwtProperties.getExpiration() * 1000);

        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("userType", userType)
                .claim("username", username)
                .claim("permissions", permissions != null ? permissions : Collections.emptyList())
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    /**
     * 验证令牌有效性
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从令牌中获取用户ID
     */
    public Long getUserIdFromToken(String token) {
        return Long.parseLong(parseClaims(token).getSubject());
    }

    /**
     * 从令牌中获取用户类型
     */
    public String getUserTypeFromToken(String token) {
        return parseClaims(token).get("userType", String.class);
    }

    /**
     * 从令牌中获取用户名
     */
    public String getUsernameFromToken(String token) {
        return parseClaims(token).get("username", String.class);
    }

    /**
     * 从令牌中获取权限列表
     */
    @SuppressWarnings("unchecked")
    public List<String> getPermissionsFromToken(String token) {
        return parseClaims(token).get("permissions", List.class);
    }

    /**
     * 从令牌中获取JTI
     */
    public String getJtiFromToken(String token) {
        return parseClaims(token).getId();
    }

    /**
     * 获取令牌过期时间（秒）
     */
    public long getExpiration() {
        return jwtProperties.getExpiration();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
