package com.macro.mall.security;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.util.JwtTokenProvider;
import com.macro.mall.config.IgnoreUrlsConfig;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * JWT认证上下文仓库（Gateway响应式环境）
 * Spring Security原生扩展点，替代GlobalFilter做认证
 */
@Component
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {

    private final JwtTokenProvider jwtTokenProvider;
    private final IgnoreUrlsConfig ignoreUrlsConfig;
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    public JwtSecurityContextRepository(JwtTokenProvider jwtTokenProvider, IgnoreUrlsConfig ignoreUrlsConfig) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.ignoreUrlsConfig = ignoreUrlsConfig;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // 无状态，不需要保存
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 白名单路径不认证
        if (isWhitelisted(path)) {
            return Mono.empty();
        }

        // OPTIONS请求不认证
        if (request.getMethod() != null && request.getMethod().name().equals("OPTIONS")) {
            return Mono.empty();
        }

        // 提取token
        String token = extractToken(request);
        if (token == null || !jwtTokenProvider.validateToken(token)) {
            return Mono.empty();
        }

        // 解析用户信息，构建认证对象
        Long userId = jwtTokenProvider.getUserIdFromToken(token);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userId, token, null);
        return Mono.just(new SecurityContextImpl(authentication));
    }

    private boolean isWhitelisted(String path) {
        return ignoreUrlsConfig.getUrls().stream()
                .anyMatch(pattern -> PATH_MATCHER.match(pattern, path));
    }

    private String extractToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(AuthConstant.JWT_TOKEN_PREFIX)) {
            return header.substring(AuthConstant.JWT_TOKEN_PREFIX.length());
        }
        return null;
    }
}
