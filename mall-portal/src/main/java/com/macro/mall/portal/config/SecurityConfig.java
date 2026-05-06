package com.macro.mall.portal.config;

import com.macro.mall.common.security.JwtAuthenticationFilter;
import com.macro.mall.common.security.JwtAuthenticationProvider;
import com.macro.mall.common.util.JwtTokenProvider;
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
 * Spring Security配置（Portal）
 * 认证：JwtAuthenticationFilter → AuthenticationManager → JwtAuthenticationProvider(expectedUserType="member")
 * 只做认证，不做细粒度权限校验
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(JwtTokenProvider jwtTokenProvider) {
        return new ProviderManager(new JwtAuthenticationProvider(jwtTokenProvider, "member"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            AuthenticationManager authenticationManager) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/sso/login", "/sso/register", "/sso/getAuthCode").permitAll()
                .requestMatchers("/home/**", "/product/**", "/brand/**", "/alipay/**").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/doc.html").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
