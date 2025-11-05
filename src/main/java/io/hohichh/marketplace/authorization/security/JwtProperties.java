package io.hohichh.marketplace.authorization.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {

    private String accessSecret;
    private String refreshSecret;
    private long accessExpirationTime;
    private long refreshExpirationTime;
}