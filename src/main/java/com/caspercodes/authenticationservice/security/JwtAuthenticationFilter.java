package com.caspercodes.authenticationservice.security;

import com.caspercodes.authenticationservice.service.TokenService;
import com.caspercodes.authenticationservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

/**
 * JWT Authentication filter that runs once per request.
 * Extracts and validates JWT token from Authorization header.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Extract Authorization header
        final String authHeader = request.getHeader("Authorization");

        // Check if header is present and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract token
            final String jwt = authHeader.substring(7);

            // Check if token is blacklisted
            if (!tokenService.isTokenValid(jwt)) {
                log.debug("Token is blacklisted");
                filterChain.doFilter(request, response);
                return;
            }

            // Extract username from token
            final String userEmail = jwtUtil.extractUsername(jwt);

            // Check if user is not already authenticated
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Validate token
                if (jwtUtil.validateToken(jwt, userEmail) && jwtUtil.isAccessToken(jwt)) {

                    // Extract user ID
                    String userId = jwtUtil.getUserIdFromToken(jwt);

                    // Create authentication token
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userEmail,
                            null,
                            new ArrayList<>() // No authorities for now
                    );

                    // Set additional details
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("User {} authenticated successfully", userEmail);
                }
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }
}