/*
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Implement the JWT (JSON Web Token) provider for the Authorization Service,
 * handling the creation, validation, and parsing of access and refresh tokens.
 */

package io.hohichh.marketplace.authentication.security;

import io.hohichh.marketplace.authentication.exception.JwtAuthenticationException;
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

    /**
     * Configuration properties for JWT, including secrets and expiration times.
     */
    private final JwtProperties jwtProperties;

    /**
     * The cryptographically secure key for signing and verifying access tokens.
     */
    private SecretKey accessSecretKey;

    /**
     * The cryptographically secure key for signing and verifying refresh tokens.
     */
    private SecretKey refreshSecretKey;

    /**
     * A Clock bean for testable time generation.
     */
    private final Clock clock;

    /**
     * Initializes the component after construction by creating the
     * HMAC-SHA secret keys from the string secrets in {@link JwtProperties}.
     */
    @PostConstruct
    protected void init() {
        this.accessSecretKey = Keys.hmacShaKeyFor(jwtProperties.getAccessSecret().getBytes());
        this.refreshSecretKey = Keys.hmacShaKeyFor(jwtProperties.getRefreshSecret().getBytes());
    }


    /**
     * Creates a new access token for a given user.
     * The token includes the user's ID as the subject and their role as a custom claim.
     *
     * @param userId The {@link UUID} of the user.
     * @param role   The role of the user (e.g., "USER", "ADMIN").
     * @return A compact, signed JWT string.
     */
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


    /**
     * Creates a new refresh token for a given user.
     * The token includes the user's ID as the subject.
     *
     * @param userId The {@link UUID} of the user.
     * @return A compact, signed JWT string.
     */
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


    /**
     * Validates a given refresh token.
     * It checks the signature, expiration, and format.
     *
     * @param token The refresh token string to validate.
     * @return {@code true} if the token is valid, {@code false} otherwise.
     */
    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(refreshSecretKey)
                    .clock(() -> Date.from(clock.instant()))
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


    /**
     * Extracts the user ID (subject) from a validated refresh token.
     * Assumes the token has been validated or will be validated by the parser.
     *
     * @param token The refresh token string.
     * @return The {@link UUID} of the user from the token's subject.
     * @throws JwtAuthenticationException if the token is invalid or the ID cannot be parsed.
     */
    public UUID getUserIdFromRefreshToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(refreshSecretKey)
                    .clock(() -> Date.from(clock.instant()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userIdStr = claims.getSubject();
            return UUID.fromString(userIdStr);

        } catch (Exception e) {
            // Catches parsing errors, signature errors, etc.
            throw new JwtAuthenticationException("Can't exctract id from jwt");
        }
    }
}