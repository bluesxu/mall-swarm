package com.macro.mall.common.security;

import com.macro.mall.common.constant.AuthConstant;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT认证过滤器
 * 提取token → 调用AuthenticationManager → 结果放入SecurityContextHolder
 * admin/portal共用，由JwtAuthenticationProvider区分用户类型
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);
        if (token != null) {
            try {
                JwtAuthenticationToken jwtToken = new JwtAuthenticationToken(token);
                Authentication result = authenticationManager.authenticate(jwtToken);
                SecurityContextHolder.getContext().setAuthentication(result);
            } catch (Exception e) {
                log.debug("JWT认证失败: {}", e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String header = request.getHeader(AuthConstant.JWT_TOKEN_HEADER);
        if (header != null && header.startsWith(AuthConstant.JWT_TOKEN_PREFIX)) {
            return header.substring(AuthConstant.JWT_TOKEN_PREFIX.length());
        }
        return null;
    }
}
