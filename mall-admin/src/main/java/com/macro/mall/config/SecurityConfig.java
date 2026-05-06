package com.macro.mall.config;

import com.macro.mall.common.security.JwtAuthenticationFilter;
import com.macro.mall.common.security.JwtAuthenticationProvider;
import com.macro.mall.common.util.JwtTokenProvider;
import com.macro.mall.security.PermissionAuthorizationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security配置（Admin）
 * 认证：JwtAuthenticationFilter → AuthenticationManager → JwtAuthenticationProvider(expectedUserType="admin")
 * 授权：PermissionAuthorizationManager（Redis路径-权限匹配）
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(JwtTokenProvider jwtTokenProvider) {
        return new ProviderManager(new JwtAuthenticationProvider(jwtTokenProvider, "admin"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager,
                                            PermissionAuthorizationManager permissionManager) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/login", "/admin/register").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/doc.html").permitAll()
                .anyRequest().access(permissionManager)
            )
            .addFilterBefore(new JwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
