package com.macro.mall.component;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.service.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 权限校验过滤器
 * 替代原网关中的权限校验逻辑，从Redis读取路径-资源映射进行权限匹配
 */
@Component
public class PermissionAuthorizationFilter extends OncePerRequestFilter {

    private final RedisService redisService;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public PermissionAuthorizationFilter(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 已认证的用户才进行权限校验
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // 从Redis获取路径-资源映射
        Map<String, List<String>> pathResourceMap = (Map<String, List<String>>) redisService.get(AuthConstant.PATH_RESOURCE_MAP);
        if (CollectionUtils.isEmpty(pathResourceMap)) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestPath = request.getRequestURI();
        // 获取用户权限列表
        Set<String> userAuthorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // 匹配请求路径与所需权限
        for (Map.Entry<String, List<String>> entry : pathResourceMap.entrySet()) {
            String pattern = entry.getKey();
            List<String> requiredResources = entry.getValue();
            if (pathMatcher.match(pattern, requestPath) && !CollectionUtils.isEmpty(requiredResources)) {
                // 检查用户是否拥有所需权限中的任意一个
                boolean hasPermission = requiredResources.stream().anyMatch(userAuthorities::contains);
                if (!hasPermission) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().write("{\"code\":403,\"message\":\"暂无权限访问\",\"data\":null}");
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
