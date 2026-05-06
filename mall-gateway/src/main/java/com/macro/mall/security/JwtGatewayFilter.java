package com.macro.mall.security;

import com.macro.mall.common.constant.AuthConstant;
import com.macro.mall.common.util.JwtTokenProvider;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Gateway请求头转发过滤器
 * 从SecurityContext中获取已认证的用户信息，添加请求头转发给下游
 * 认证逻辑已移至JwtSecurityContextRepository
 */
@Component
public class JwtGatewayFilter implements GlobalFilter, Ordered {

    private final JwtTokenProvider jwtTokenProvider;

    public JwtGatewayFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .cast(UsernamePasswordAuthenticationToken.class)
                .map(UsernamePasswordAuthenticationToken::getCredentials)
                .cast(String.class)
                .flatMap(token -> {
                    JwtTokenProvider.TokenInfo info = jwtTokenProvider.parseTokenInfo(token);

                    var enriched = exchange.getRequest().mutate()
                            .header(AuthConstant.USER_ID_HEADER, String.valueOf(info.userId()))
                            .header(AuthConstant.USER_TYPE_HEADER, info.userType())
                            .header(AuthConstant.USERNAME_HEADER, info.username())
                            .header(AuthConstant.PERMISSIONS_HEADER,
                                    info.permissions() != null ? String.join(",", info.permissions()) : "")
                            .build();

                    return chain.filter(exchange.mutate().request(enriched).build());
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
