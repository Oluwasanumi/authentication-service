package com.caspercodes.authenticationservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Service for sending emails.
 * Uses @Async for non-blocking email sending.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.email.from}")
    private String fromEmail;

    /**
     * Send OTP email for email verification
     */
    @Async
    public void sendVerificationEmail(String to, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Verify Your Email - CasperCodes");

            String htmlContent = buildVerificationEmailContent(otp);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send verification email to: {}", to, e);
            // In production, you might want to implement retry logic or use a message queue
        }
    }

    /**
     * Send OTP email for password reset
     */
    @Async
    public void sendPasswordResetEmail(String to, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Password Reset Request - CasperCodes");

            String htmlContent = buildPasswordResetEmailContent(otp);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to: {}", to, e);
        }
    }

    /**
     * Build HTML content for verification email
     */
    private String buildVerificationEmailContent(String otp) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #007bff; color: white; padding: 20px; text-align: center; }
                        .content { background-color: #f4f4f4; padding: 20px; margin-top: 20px; }
                        .otp-code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; 
                                    padding: 20px; background-color: white; border-radius: 5px; margin: 20px 0; }
                        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Email Verification</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>Thank you for registering with CasperCodes. Please use the following OTP to verify your email address:</p>
                            <div class="otp-code">%s</div>
                            <p>This code will expire in 5 minutes.</p>
                            <p>If you didn't request this verification, please ignore this email.</p>
                        </div>
                        <div class="footer">
                            <p>&copy; 2024 CasperCodes. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(otp);
    }

    /**
     * Build HTML content for password reset email
     */
    private String buildPasswordResetEmailContent(String otp) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; }
                        .content { background-color: #f4f4f4; padding: 20px; margin-top: 20px; }
                        .otp-code { font-size: 32px; font-weight: bold; color: #dc3545; text-align: center; 
                                    padding: 20px; background-color: white; border-radius: 5px; margin: 20px 0; }
                        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
                        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; 
                                  border-radius: 5px; margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Password Reset Request</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>We received a request to reset your password. Use the following OTP to complete the process:</p>
                            <div class="otp-code">%s</div>
                            <p>This code will expire in 5 minutes.</p>
                            <div class="warning">
                                <p><strong>Security Notice:</strong> If you didn't request a password reset, 
                                   please ignore this email and ensure your account is secure.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>&copy; 2024 CasperCodes. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(otp);
    }
}