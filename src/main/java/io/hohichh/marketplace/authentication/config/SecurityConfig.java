/*
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Configure the Spring Security settings for the Authorization Service,
 * defining password encoding and HTTP security rules.
 */

package io.hohichh.marketplace.authentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Configure the Spring Security settings for the Authorization Service,
 * defining password encoding and HTTP security rules.
 *
 * This class sets up the web security for the application. It disables CSRF,
 * enforces stateless sessions, and defines which endpoints are public
 * (like /v1/auth/**) and which require authentication.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Creates a {@link PasswordEncoder} bean to be used for hashing and validating passwords.
     * This implementation uses the strong BCrypt hashing algorithm.
     *
     * @return a {@link BCryptPasswordEncoder} instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Configures the main security filter chain for the application.
     *
     * This filter chain:
     * 1. Disables CSRF protection (suitable for stateless REST APIs).
     * 2. Sets the session management policy to STATELESS.
     * 3. Configures authorization rules:
     * - Permits all requests to paths starting with "/v1/auth/**" (e.g., login, register).
     * - Requires authentication for all other requests.
     *
     * @param http the {@link HttpSecurity} to be configured.
     * @return the configured {@link SecurityFilterChain}.
     * @throws Exception if an error occurs during the configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.POST, "/v1/auth/login",
                                "/v1/auth/refresh",
                                "/v1/auth/credentials").permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}