package com.ust.Security.Controller;

import com.ust.Security.dto.ForgotPasswordRequest;
import com.ust.Security.dto.ResetPasswordRequest;
import com.ust.Security.model.Userinfo;
import com.ust.Security.service.JwtService;
import com.ust.Security.service.Userservices;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class ForgotPasswordController {

    @Autowired
    private Userservices userService;

    @Autowired
    private JwtService jwtService;
    
    // Endpoint to initiate forgot password process
    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        String email = request.getEmail();
        Userinfo user = userService.findByEmail(email);
        if (user == null) {
            return ResponseEntity.badRequest().body("No user found with the provided email.");
        }
        // Generate a reset token (JWT) with a short expiration time
        String resetToken = jwtService.generateResetToken(email);
        
        // TODO: Integrate email service to send the reset token link to user's email address
        // For demonstration, we return the token in the response.
        return ResponseEntity.ok("Password reset token: " + resetToken);
    }
    
    // Endpoint to reset password using the reset token and new password
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        String token = request.getToken();
        String newPassword = request.getNewPassword();
        
        if (!jwtService.validateResetToken(token)) {
            return ResponseEntity.badRequest().body("Invalid or expired reset token.");
        }
        
        // Extract email (subject) from the token
        String email = jwtService.extractUsername(token);
        Userinfo user = userService.findByEmail(email);
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found.");
        }
        
        // Update the password (remember to hash the password)
        userService.updatePassword(user, newPassword);
        return ResponseEntity.ok("Password has been reset successfully.");
    }
}

