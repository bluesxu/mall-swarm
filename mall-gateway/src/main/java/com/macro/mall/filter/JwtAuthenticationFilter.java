package com.macro.mall.filter;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.util.JwtTokenProvider;
import com.macro.mall.config.IgnoreUrlsConfig;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * JWT认证过滤器（响应式环境）
 * 网关只做登录校验和用户信息转发，不做权限校验
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtTokenProvider jwtTokenProvider;
    private final IgnoreUrlsConfig ignoreUrlsConfig;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, IgnoreUrlsConfig ignoreUrlsConfig) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.ignoreUrlsConfig = ignoreUrlsConfig;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 白名单路径放行
        List<String> ignoreUrls = ignoreUrlsConfig.getUrls();
        for (String ignoreUrl : ignoreUrls) {
            if (pathMatcher.match(ignoreUrl, path)) {
                return chain.filter(exchange);
            }
        }

        // OPTIONS请求放行
        if (request.getMethod() != null && request.getMethod().name().equals("OPTIONS")) {
            return chain.filter(exchange);
        }

        // 从请求头中获取token
        String token = resolveToken(request);
        if (!StringUtils.hasText(token)) {
            return unauthorizedResponse(exchange, "未提供认证令牌");
        }

        // 验证token
        if (!jwtTokenProvider.validateToken(token)) {
            return unauthorizedResponse(exchange, "认证令牌无效或已过期");
        }

        // 解析token，添加请求头转发
        Long userId = jwtTokenProvider.getUserIdFromToken(token);
        String username = jwtTokenProvider.getUsernameFromToken(token);
        String userType = jwtTokenProvider.getUserTypeFromToken(token);
        List<String> permissions = jwtTokenProvider.getPermissionsFromToken(token);

        // 将用户信息通过请求头传递给下游微服务
        ServerHttpRequest mutatedRequest = request.mutate()
                .header(AuthConstant.USER_ID_HEADER, String.valueOf(userId))
                .header(AuthConstant.USER_TYPE_HEADER, userType)
                .header(AuthConstant.USERNAME_HEADER, username)
                .header(AuthConstant.PERMISSIONS_HEADER,
                        permissions != null ? String.join(",", permissions) : "")
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AuthConstant.JWT_TOKEN_PREFIX)) {
            return bearerToken.substring(AuthConstant.JWT_TOKEN_PREFIX.length());
        }
        return null;
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set("Content-Type", "application/json;charset=UTF-8");
        String body = "{\"code\":401,\"message\":\"" + message + "\",\"data\":null}";
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes())));
    }
}
