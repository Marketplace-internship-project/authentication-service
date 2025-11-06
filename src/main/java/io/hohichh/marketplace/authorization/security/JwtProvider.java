package io.hohichh.marketplace.authorization.security;

import io.hohichh.marketplace.authorization.exception.JwtAuthenticationException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

import java.time.Clock;


@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    private SecretKey accessSecretKey;
    private SecretKey refreshSecretKey;

    private final Clock clock;

    @PostConstruct
    protected void init() {
        this.accessSecretKey = Keys.hmacShaKeyFor(jwtProperties.getAccessSecret().getBytes());
        this.refreshSecretKey = Keys.hmacShaKeyFor(jwtProperties.getRefreshSecret().getBytes());
    }


    public String createAccessToken(UUID userId, String role) {
        Claims claims = Jwts.claims()
                .subject(userId.toString())
                .add("role", role)
                .build();

        Date now = Date.from(clock.instant());
        Date validity = Date.from(now.toInstant().plusMillis(jwtProperties.getAccessExpirationTime()));

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(validity)
                .signWith(accessSecretKey)
                .compact();
    }


    public String createRefreshToken(UUID userId) {
        Claims claims = Jwts.claims().subject(userId.toString()).build();

        Date now = Date.from(clock.instant());
        Date validity = Date.from(now.toInstant().plusMillis(jwtProperties.getRefreshExpirationTime()));

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(validity)
                .signWith(refreshSecretKey)
                .compact();
    }


    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(refreshSecretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Refresh token has expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported Refresh token: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("Invalid Refresh token: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("Wrong signature of Refresh token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("empty Refresh token: {}", e.getMessage());
        }

        return false;
    }


    public UUID getUserIdFromRefreshToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(refreshSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userIdStr = claims.getSubject();
            return UUID.fromString(userIdStr);

        } catch (Exception e) {
            throw new JwtAuthenticationException("Can't exctract id from jwt");
        }
    }
}