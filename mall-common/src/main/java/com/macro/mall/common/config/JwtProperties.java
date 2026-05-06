package com.macro.mall.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * JWT配置属性
 */
@Data
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /**
     * JWT签名密钥
     */
    private String secret;

    /**
     * JWT过期时间（秒），默认7天
     */
    private long expiration = 604800;
}
