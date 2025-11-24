package io.hohichh.marketplace.authentication.security;


import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null && jwtProvider.validateAccessToken(token)) {
            try {
                Claims claims = jwtProvider.getAccessClaims(token);
                String userId = claims.getSubject();
                String role = claims.get("role", String.class);

                Authentication auth = createAuthentication(userId, role);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                log.error("Cannot set user authentication: {}", e.getMessage());
                }
        }

        filterChain.doFilter(request, response);
    }

    private Authentication createAuthentication(String userId, String role) {
        List<SimpleGrantedAuthority> authorities = Collections.emptyList();
        if (role != null && !role.isBlank()) {
            String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            authorities = List.of(new SimpleGrantedAuthority(authority));
        }
        return new UsernamePasswordAuthenticationToken(userId, null, authorities);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}
