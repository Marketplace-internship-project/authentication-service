/*
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Implement the REST controller layer for the Authorization Service,
 * providing API endpoints for credential creation, user login, and token refreshing.
 */

package io.hohichh.marketplace.authentication.controller;

import io.hohichh.marketplace.authentication.dto.*;

import io.hohichh.marketplace.authentication.service.UserCredentialsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Implement the REST controller layer for the Authorization Service,
 * providing API endpoints for credential creation, user login, and token refreshing.
 *
 * This controller handles all public-facing authentication requests,
 * delegating the business logic to the {@link UserCredentialsService}.
 */
@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class RestAuthController {

    /**
     * The service responsible for handling the business logic of authentication.
     */
    private final UserCredentialsService userCredentialsService;

    /**
     * Saves new user credentials.
     *
     * @param createDto The DTO containing the new user's login, password, and associated userId.
     * @return A ResponseEntity containing the created {@link UserCredentialsResponseDto} and HTTP status 201 (Created).
     */
    @PostMapping("/credentials")
    public ResponseEntity<UserCredentialsResponseDto> saveUserCredentials(
            @RequestBody UserCredentialsCreateDto createDto) {

        UserCredentialsResponseDto response = userCredentialsService.saveUserCredentials(createDto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Authenticates a user based on their login and password.
     * If successful, it returns a pair of access and refresh tokens.
     *
     * @param loginDto The DTO containing the user's login and password.
     * @return A ResponseEntity containing the {@link LoginResponseDto} (access/refresh tokens) and HTTP status 200 (OK).
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
            @RequestBody LoginRequestDto loginDto) {

        LoginResponseDto response = userCredentialsService.login(loginDto);
        return ResponseEntity.ok(response);
    }

    /**
     * Refreshes the user's access and refresh tokens using a valid refresh token.
     *
     * @param refreshDto The DTO containing the existing (and valid) refresh token.
     * @return A ResponseEntity containing a new {@link LoginResponseDto} (a new pair of tokens) and HTTP status 200 (OK).
     */
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(
            @RequestBody RefreshTokenRequestDto refreshDto) {

        LoginResponseDto response = userCredentialsService.refresh(refreshDto);
        return ResponseEntity.ok(response);
    }
}