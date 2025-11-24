package io.hohichh.marketplace.authentication.service;

import io.hohichh.marketplace.authentication.dto.LoginRequestDto;
import io.hohichh.marketplace.authentication.dto.LoginResponseDto;
import io.hohichh.marketplace.authentication.dto.RefreshTokenRequestDto;
import io.hohichh.marketplace.authentication.dto.UserCredentialsCreateDto;
import io.hohichh.marketplace.authentication.dto.UserCredentialsResponseDto;

import java.util.UUID;

public interface UserCredentialsService {
    UserCredentialsResponseDto saveUserCredentials(UserCredentialsCreateDto createDto);
    void deleteUserCredentialsByUserId(UUID userId);
    LoginResponseDto login(LoginRequestDto loginDto);
    LoginResponseDto refresh(RefreshTokenRequestDto refreshDto);
}