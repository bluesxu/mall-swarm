package com.macro.mall.config;

import com.macro.mall.security.JwtSecurityContextRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Spring Security配置（Gateway WebFlux环境）
 * 认证由JwtSecurityContextRepository处理，Gateway只做token验证和请求头转发
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                          JwtSecurityContextRepository securityContextRepository) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .securityContextRepository(securityContextRepository)
            .authorizeExchange(exchange -> exchange.anyExchange().permitAll())
            .build();
    }
}
