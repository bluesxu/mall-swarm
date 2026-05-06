package com.macro.mall.common.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;
import java.util.List;

/**
 * JWT认证令牌
 * 未认证状态：只携带token，提交给AuthenticationManager
 * 已认证状态：携带userId、token、userType、permissions
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Long userId;
    private final String token;
    private final String userType;

    /** 未认证状态，用于提交给AuthenticationManager */
    public JwtAuthenticationToken(String token) {
        super(Collections.emptyList());
        this.userId = null;
        this.token = token;
        this.userType = null;
        setAuthenticated(false);
    }

    /** 已认证状态，由AuthenticationProvider返回 */
    public JwtAuthenticationToken(Long userId, String token, String userType, List<String> permissions) {
        super(permissions != null
                ? permissions.stream().map(p -> (org.springframework.security.core.GrantedAuthority) () -> p).toList()
                : Collections.emptyList());
        this.userId = userId;
        this.token = token;
        this.userType = userType;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    public String getToken() {
        return token;
    }

    public String getUserType() {
        return userType;
    }

    public Long getUserId() {
        return userId;
    }
}
