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

    public ApiResponse<UserInfo> signUp(SignUpRequest request) {
        log.debug("Processing sign up for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException(request.getEmail());
        }

        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .emailVerified(false)
                .enabled(true)
                .failedLoginAttempts(0)
                .build();

        user = userRepository.save(user);
        log.info("User created with id: {}", user.getId());

        sendVerificationOtp(user.getEmail());

        UserInfo userInfo = UserInfo.builder()
                .id(user.getId())
                .email(user.getEmail())
                .emailVerified(user.isEmailVerified())
                .createdAt(user.getCreatedAt())
                .build();

        return ApiResponse.success("User registered successfully. Please check your email for verification code.", userInfo);
    }

    public ApiResponse<AuthResponse> login(LoginRequest request) {
        log.debug("Processing login for email: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
            userRepository.save(user);
            throw new InvalidCredentialsException();
        }

        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException();
        }

        if (!user.isEnabled()) {
            throw new AuthenticationException("Account is disabled");
        }

        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        String tokenId = UUID.randomUUID().toString();
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId(), user.getEmail());

        tokenService.storeAccessToken(user.getId(), accessToken, tokenId);
        tokenService.storeRefreshToken(user.getId(), refreshToken, tokenId);

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

    public ApiResponse<Void> verifyEmail(VerifyOtpRequest request) {
        log.debug("Verifying email for: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new UserNotFoundException(request.getEmail()));

        if (user.isEmailVerified()) {
            return ApiResponse.success("Email already verified");
        }

        verifyOtp(request.getEmail(), request.getCode(), OtpToken.OtpType.EMAIL_VERIFICATION);

        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {}", user.getId());
        return ApiResponse.success("Email verified successfully");
    }

    public ApiResponse<Void> forgotPassword(ForgotPasswordRequest request) {
        log.debug("Processing forgot password for: {}", request.getEmail());

        userRepository.findByEmail(request.getEmail().toLowerCase())
                .ifPresent(user -> {
                    sendPasswordResetOtp(user.getEmail());
                });

        return ApiResponse.success("If the email exists, a password reset code has been sent");
    }

    public ApiResponse<Void> resetPassword(ResetPasswordRequest request) {
        log.debug("Processing password reset for: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new UserNotFoundException(request.getEmail()));

        verifyOtp(request.getEmail(), request.getCode(), OtpToken.OtpType.PASSWORD_RESET);

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordResetAt(LocalDateTime.now());
        userRepository.save(user);

        tokenService.removeAllUserTokens(user.getId());

        log.info("Password reset for user: {}", user.getId());
        return ApiResponse.success("Password reset successfully");
    }

    public ApiResponse<AuthResponse> refreshToken(RefreshTokenRequest request) {
        log.debug("Processing token refresh");

        String refreshToken = request.getRefreshToken();

        if (!jwtUtil.isRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        if (!tokenService.isTokenValid(refreshToken)) {
            throw new InvalidTokenException("Token has been revoked");
        }

        String email = jwtUtil.extractUsername(refreshToken);
        String userId = jwtUtil.getUserIdFromToken(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, email)) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(email));

        if (!user.isEnabled() || !user.isEmailVerified()) {
            throw new AuthenticationException("User account is not active");
        }

        String tokenId = UUID.randomUUID().toString();
        String newAccessToken = jwtUtil.generateAccessToken(userId, email);

        tokenService.storeAccessToken(userId, newAccessToken, tokenId);

        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken) // Return same refresh token
                .tokenType("Bearer")
                .expiresIn(3600)
                .user(UserInfo.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .emailVerified(user.isEmailVerified())
                        .createdAt(user.getCreatedAt())
                        .build())
                .build();

        return ApiResponse.success("Token refreshed successfully", authResponse);
    }

    public ApiResponse<Void> logout(String token) {
        log.debug("Processing logout");

        long expirationTime = jwtUtil.extractExpiration(token).getTime() - System.currentTimeMillis();

        tokenService.blacklistToken(token, expirationTime);

        return ApiResponse.success("Logged out successfully");
    }

    public ApiResponse<Void> logoutAllDevices(String userId) {
        log.debug("Processing logout from all devices for user: {}", userId);

        tokenService.removeAllUserTokens(userId);

        return ApiResponse.success("Logged out from all devices successfully");
    }

    private void sendVerificationOtp(String email) {
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long recentOtpCount = otpTokenRepository.countByEmailAndTypeAndUsedFalseAndCreatedAtAfter(
                email, OtpToken.OtpType.EMAIL_VERIFICATION, oneHourAgo);

        if (recentOtpCount >= 3) {
            throw new RateLimitExceededException("Too many OTP requests. Please try again later.");
        }

        String otpCode = otpGenerator.generateOtp();
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(otpExpiration / 1000);

        OtpToken otpToken = OtpToken.builder()
                .email(email)
                .code(otpCode)
                .type(OtpToken.OtpType.EMAIL_VERIFICATION)
                .createdAt(LocalDateTime.now())
                .expiresAt(expiresAt)
                .used(false)
                .attempts(0)
                .build();

        otpTokenRepository.save(otpToken);

        emailService.sendVerificationEmail(email, otpCode);
        log.info("Verification OTP sent to: {}", email);
    }

    private void sendPasswordResetOtp(String email) {
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long recentOtpCount = otpTokenRepository.countByEmailAndTypeAndUsedFalseAndCreatedAtAfter(
                email, OtpToken.OtpType.PASSWORD_RESET, oneHourAgo);

        if (recentOtpCount >= 3) {
            throw new RateLimitExceededException("Too many password reset requests. Please try again later.");
        }

        String otpCode = otpGenerator.generateOtp();
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(otpExpiration / 1000);

        OtpToken otpToken = OtpToken.builder()
                .email(email)
                .code(otpCode)
                .type(OtpToken.OtpType.PASSWORD_RESET)
                .createdAt(LocalDateTime.now())
                .expiresAt(expiresAt)
                .used(false)
                .attempts(0)
                .build();

        otpTokenRepository.save(otpToken);

        emailService.sendPasswordResetEmail(email, otpCode);
        log.info("Password reset OTP sent to: {}", email);
    }

    private void verifyOtp(String email, String code, OtpToken.OtpType type) {
        OtpToken otpToken = otpTokenRepository.findValidOtp(
                        email, code, type, LocalDateTime.now())
                .orElseThrow(InvalidOtpException::new);

        if (otpToken.getAttempts() >= 3) {
            throw new InvalidOtpException();
        }

        otpToken.setUsed(true);
        otpTokenRepository.save(otpToken);
    }

    public ApiResponse<Void> resendOtp(String email, OtpToken.OtpType type) {
        log.debug("Resending OTP for: {} - Type: {}", email, type);

        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new UserNotFoundException(email));

        if (type == OtpToken.OtpType.EMAIL_VERIFICATION) {
            if (user.isEmailVerified()) {
                return ApiResponse.success("Email already verified");
            }
            sendVerificationOtp(email);
        } else {
            sendPasswordResetOtp(email);
        }

        return ApiResponse.success("OTP sent successfully");
    }
}