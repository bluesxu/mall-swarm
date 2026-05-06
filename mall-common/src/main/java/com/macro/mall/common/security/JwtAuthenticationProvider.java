package com.macro.mall.common.security;

import com.macro.mall.common.util.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import java.util.List;

/**
 * JWT认证提供者
 * 通过expectedUserType参数区分admin/member，由各模块SecurityConfig配置
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtTokenProvider jwtTokenProvider;
    private final String expectedUserType;

    public JwtAuthenticationProvider(JwtTokenProvider jwtTokenProvider, String expectedUserType) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.expectedUserType = expectedUserType;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        String token = jwtToken.getToken();

        if (!jwtTokenProvider.validateToken(token)) {
            throw new BadCredentialsException("认证令牌无效或已过期");
        }

        String userType = jwtTokenProvider.getUserTypeFromToken(token);
        if (!expectedUserType.equals(userType)) {
            throw new BadCredentialsException("无效的用户类型");
        }

        Long userId = jwtTokenProvider.getUserIdFromToken(token);
        List<String> permissions = jwtTokenProvider.getPermissionsFromToken(token);

        return new JwtAuthenticationToken(userId, token, userType, permissions);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
