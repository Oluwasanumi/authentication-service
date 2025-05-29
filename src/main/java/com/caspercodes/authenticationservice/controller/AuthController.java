package com.caspercodes.authenticationservice.controller;

import com.caspercodes.authenticationservice.dto.*;
import com.caspercodes.authenticationservice.entity.OtpToken;
import com.caspercodes.authenticationservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for authentication endpoints.
 *
 * @RestController = @Controller + @ResponseBody
 * @RequestMapping defines the base path for all endpoints in this controller
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    /**
     * Sign up endpoint
     * POST /api/auth/signup
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserInfo>> signUp(@Valid @RequestBody SignUpRequest request) {
        log.info("Sign up request received for email: {}", request.getEmail());
        ApiResponse<UserInfo> response = authService.signUp(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Login endpoint
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for email: {}", request.getEmail());
        ApiResponse<AuthResponse> response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Verify email endpoint
     * POST /api/auth/verify-email
     */
    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@Valid @RequestBody VerifyOtpRequest request) {
        log.info("Email verification request received for: {}", request.getEmail());
        ApiResponse<Void> response = authService.verifyEmail(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Forgot password endpoint
     * POST /api/auth/forgot-password
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        log.info("Forgot password request received for: {}", request.getEmail());
        ApiResponse<Void> response = authService.forgotPassword(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Reset password endpoint
     * POST /api/auth/reset-password
     */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        log.info("Password reset request received for: {}", request.getEmail());
        ApiResponse<Void> response = authService.resetPassword(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Refresh token endpoint
     * POST /api/auth/refresh-token
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request received");
        ApiResponse<AuthResponse> response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Resend OTP endpoint
     * POST /api/auth/resend-otp
     */
    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse<Void>> resendOtp(
            @RequestParam String email,
            @RequestParam OtpToken.OtpType type) {
        log.info("Resend OTP request received for: {} - Type: {}", email, type);
        ApiResponse<Void> response = authService.resendOtp(email, type);
        return ResponseEntity.ok(response);
    }

    /**
     * Logout endpoint (requires authentication)
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String authHeader) {
        log.info("Logout request received");
        // Extract token from header
        String token = authHeader.substring(7);
        ApiResponse<Void> response = authService.logout(token);
        return ResponseEntity.ok(response);
    }

    /**
     * Logout from all devices endpoint (requires authentication)
     * POST /api/auth/logout-all
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAllDevices() {
        log.info("Logout all devices request received");
        // Get authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // For this endpoint, we need to get the user ID from the service
        // In a real application, you might store user ID in the authentication principal
        // For now, we'll use email to look up the user

        // This would be better handled by storing user ID in JWT claims
        return ResponseEntity.ok(ApiResponse.success("Feature coming soon"));
    }

    /**
     * Test endpoint to verify authentication (requires authentication)
     * GET /api/auth/me
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<String>> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return ResponseEntity.ok(ApiResponse.success("Authenticated user", email));
    }
}