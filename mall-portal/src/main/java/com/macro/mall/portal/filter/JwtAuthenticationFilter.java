package com.macro.mall.portal.filter;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.util.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 * JWT认证过滤器（Portal Servlet环境）
 * 从请求头中解析JWT令牌，验证userType为member，构建认证信息
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);
        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            String userType = jwtTokenProvider.getUserTypeFromToken(token);
            // 只允许member类型的token访问portal接口
            if (!"member".equals(userType)) {
                filterChain.doFilter(request, response);
                return;
            }

            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            String username = jwtTokenProvider.getUsernameFromToken(token);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 将用户信息放入请求属性，供下游使用
            request.setAttribute(AuthConstant.USER_ID_HEADER, userId);
            request.setAttribute(AuthConstant.USERNAME_HEADER, username);
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AuthConstant.JWT_TOKEN_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AuthConstant.JWT_TOKEN_PREFIX)) {
            return bearerToken.substring(AuthConstant.JWT_TOKEN_PREFIX.length());
        }
        return null;
    }
}
