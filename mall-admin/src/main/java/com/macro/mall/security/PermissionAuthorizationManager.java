package com.macro.mall.security;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.service.RedisService;
import com.macro.mall.common.util.JwtTokenProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 基于Redis路径-资源映射的权限授权管理器
 * 从Redis读取pathResourceMap，AntPathMatcher匹配请求路径，校验用户JWT中的权限列表
 */
@Component
public class PermissionAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final RedisService redisService;
    private final JwtTokenProvider jwtTokenProvider;
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    public PermissionAuthorizationManager(RedisService redisService, JwtTokenProvider jwtTokenProvider) {
        this.redisService = redisService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }

        String requestUri = context.getRequest().getRequestURI();
        Map<Object, Object> pathResourceMap = redisService.hGetAll(AuthConstant.PATH_RESOURCE_MAP);

        // 遍历路径资源映射，找到匹配的资源
        for (Map.Entry<Object, Object> entry : pathResourceMap.entrySet()) {
            String pattern = (String) entry.getKey();
            if (PATH_MATCHER.match(pattern, requestUri)) {
                String requiredResource = (String) entry.getValue();
                // 从token中获取权限列表进行校验
                String token = (String) auth.getCredentials();
                List<String> userPermissions = jwtTokenProvider.getPermissionsFromToken(token);
                if (userPermissions != null && userPermissions.contains(requiredResource)) {
                    return new AuthorizationDecision(true);
                }
                return new AuthorizationDecision(false);
            }
        }
        // 路径不在资源映射中，放行
        return new AuthorizationDecision(true);
    }
}
