package com.rih.backend.controller;


import com.rih.backend.dto.LoginUserDto;
import com.rih.backend.dto.RegisterUserDto;
import com.rih.backend.dto.VerifyUserDto;
import com.rih.backend.model.User;
import com.rih.backend.responses.LoginResponse;
import com.rih.backend.service.AuthService;
import com.rih.backend.service.JwtService;

import lombok.AllArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling authentication-related operations.
 */
@RequestMapping("/auth")
@RestController
@AllArgsConstructor
public class AuthenticationController {
    private final JwtService jwtService;

    private final AuthService authService;

    /**
     * Registers a new user.
     *
     * @param registerUserDto The user registration details.
     * @return ResponseEntity containing the registered user details.
     */
    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authService.signup(registerUserDto);
        return ResponseEntity.ok(registeredUser);
    }

    /**
     * Authenticates a user and generates a JWT token.
     *
     * @param loginUserDto The user login details.
     * @return ResponseEntity containing the JWT token and expiration time.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto){
        User authenticatedUser = authService.authenticate(loginUserDto);
        String jwtToken = jwtService.generateToken(authenticatedUser);
        LoginResponse loginResponse = new LoginResponse(jwtToken, jwtService.getExpirationTime());
        return ResponseEntity.ok(loginResponse);
    }

    /**
     * Verifies a user's account using the provided verification details.
     *
     * @param verifyUserDto The verification details.
     * @return ResponseEntity indicating success or failure.
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        try {
            authService.verifyUser(verifyUserDto);
            return ResponseEntity.ok("Account verified successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    /**
     * Resends a verification code to the user's email.
     *
     * @param email The user's email address.
     * @return ResponseEntity indicating whether the code was sent successfully.
     */
    @PostMapping("/resend")
    public ResponseEntity<?> resendVerificationCode(@RequestParam String email) {
        try {
            authService.resendVerificationCode(email);
            return ResponseEntity.ok("Verification code sent");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}