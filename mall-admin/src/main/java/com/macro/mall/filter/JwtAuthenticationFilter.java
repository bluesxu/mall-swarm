package com.macro.mall.filter;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.util.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT认证过滤器（Servlet环境）
 * 从请求头中解析JWT令牌，验证userType为admin，构建认证信息
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
            // 只允许admin类型的token访问admin接口
            if (!"admin".equals(userType)) {
                filterChain.doFilter(request, response);
                return;
            }

            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            String username = jwtTokenProvider.getUsernameFromToken(token);
            List<String> permissions = jwtTokenProvider.getPermissionsFromToken(token);

            List<SimpleGrantedAuthority> authorities = permissions.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
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
