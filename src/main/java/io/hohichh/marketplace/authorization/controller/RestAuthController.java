package io.hohichh.marketplace.authorization.controller;

import io.hohichh.marketplace.authorization.dto.*;
import io.hohichh.marketplace.authorization.service.UserCredentialsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class RestAuthController {

    private final UserCredentialsService userCredentialsService;

    @PostMapping("/credentials")
    public ResponseEntity<UserCredentialsResponseDto> saveUserCredentials(
            @RequestBody UserCredentialsCreateDto createDto) {

        UserCredentialsResponseDto response = userCredentialsService.saveUserCredentials(createDto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
            @RequestBody LoginRequestDto loginDto) {

        LoginResponseDto response = userCredentialsService.login(loginDto);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(
            @RequestBody RefreshTokenRequestDto refreshDto) {

        LoginResponseDto response = userCredentialsService.refresh(refreshDto);
        return ResponseEntity.ok(response);
    }
}