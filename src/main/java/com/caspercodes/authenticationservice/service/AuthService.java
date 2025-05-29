package com.caspercodes.authenticationservice.service;

import com.caspercodes.authenticationservice.dto.*;
import com.caspercodes.authenticationservice.entity.OtpToken;
import com.caspercodes.authenticationservice.entity.User;
import com.caspercodes.authenticationservice.exception.*;
import com.caspercodes.authenticationservice.repository.OtpTokenRepository;
import com.caspercodes.authenticationservice.repository.UserRepository;
import com.caspercodes.authenticationservice.util.JwtUtil;
import com.caspercodes.authenticationservice.util.OtpGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Main authentication service containing business logic.
 *
 * @Transactional ensures database operations are atomic
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;
    private final EmailService emailService;
    private final OtpGenerator otpGenerator;

    @Value("${app.otp.expiration}")
    private Long otpExpiration;

    /**
     * Register new user
     */
    public ApiResponse<UserInfo> signUp(SignUpRequest request) {
        log.debug("Processing sign up for email: {}", request.getEmail());

        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException(request.getEmail());
        }

        // Create new user
        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .emailVerified(false)
                .enabled(true)
                .failedLoginAttempts(0)
                .build();

        user = userRepository.save(user);
        log.info("User created with id: {}", user.getId());

        // Generate and send OTP
        sendVerificationOtp(user.getEmail());

        // Convert to UserInfo DTO
        UserInfo userInfo = UserInfo.builder()
                .id(user.getId())
                .email(user.getEmail())
                .emailVerified(user.isEmailVerified())
                .createdAt(user.getCreatedAt())
                .build();

        return ApiResponse.success("User registered successfully. Please check your email for verification code.", userInfo);
    }

    /**
     * Authenticate user and generate tokens
     */
    public ApiResponse<AuthResponse> login(LoginRequest request) {
        log.debug("Processing login for email: {}", request.getEmail());

        // Find user
        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new InvalidCredentialsException());

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            // Increment failed login attempts
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
            userRepository.save(user);
            throw new InvalidCredentialsException();
        }

        // Check if email is verified
        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException();
        }

        // Check if account is enabled
        if (!user.isEnabled()) {
            throw new AuthenticationException("Account is disabled");
        }

        // Reset failed login attempts and update last login
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate tokens
        String tokenId = UUID.randomUUID().toString();
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId(), user.getEmail());

        // Store tokens in Redis
        tokenService.storeAccessToken(user.getId(), accessToken, tokenId);
        tokenService.storeRefreshToken(user.getId(), refreshToken, tokenId);

        // Build response
        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(3600) // 1 hour in seconds
                .user(UserInfo.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .emailVerified(user.isEmailVerified())
                        .createdAt(user.getCreatedAt())
                        .build())
                .build();

        return ApiResponse.success("Login successful", authResponse);
    }

    /**
     * Verify email with OTP
     */
    public ApiResponse<Void> verifyEmail(VerifyOtpRequest request) {
        log.debug("Verifying email for: {}", request.getEmail());

        // Find user
        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new UserNotFoundException(request.getEmail()));

        // Check if already verified
        if (user.isEmailVerified()) {
            return ApiResponse.success("Email already verified");
        }

        // Verify OTP
        verifyOtp(request.getEmail(), request.getCode(), OtpToken.OtpType.EMAIL_VERIFICATION);

        // Update user
        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {}", user.getId());
        return ApiResponse.success("Email verified successfully");
    }

    /**
     * Initiate password reset
     */
    public ApiResponse<Void> forgotPassword(ForgotPasswordRequest request) {
        log.debug("Processing forgot password for: {}", request.getEmail());

        // Find user (don't reveal if user exists or not for security)
        userRepository.findByEmail(request.getEmail().toLowerCase())
                .ifPresent(user -> {
                    // Send password reset OTP
                    sendPasswordResetOtp(user.getEmail());
                });

        // Always return success message
        return ApiResponse.success("If the email exists, a password reset code has been sent");
    }

    /**
     * Reset password with OTP
     */
    public ApiResponse<Void> resetPassword(ResetPasswordRequest request) {
        log.debug("Processing password reset for: {}", request.getEmail());

        // Find user
        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new UserNotFoundException(request.getEmail()));

        // Verify OTP
        verifyOtp(request.getEmail(), request.getCode(), OtpToken.OtpType.PASSWORD_RESET);

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordResetAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate all tokens for security
        tokenService.removeAllUserTokens(user.getId());

        log.info("Password reset for user: {}", user.getId());
        return ApiResponse.success("Password reset successfully");
    }

/**