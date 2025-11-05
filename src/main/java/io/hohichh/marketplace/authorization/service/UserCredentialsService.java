package io.hohichh.marketplace.authorization.service;

import io.hohichh.marketplace.authorization.dto.LoginRequestDto;
import io.hohichh.marketplace.authorization.dto.LoginResponseDto;
import io.hohichh.marketplace.authorization.dto.RefreshTokenRequestDto;
import io.hohichh.marketplace.authorization.dto.UserCredentialsCreateDto;
import io.hohichh.marketplace.authorization.dto.UserCredentialsResponseDto;
import org.springframework.data.crossstore.ChangeSetPersister;

public interface UserCredentialsService {
    UserCredentialsResponseDto saveUserCredentials(UserCredentialsCreateDto createDto) throws ChangeSetPersister.NotFoundException;
    LoginResponseDto login(LoginRequestDto loginDto);
    LoginResponseDto refresh(RefreshTokenRequestDto refreshDto);
}