package io.hohichh.marketplace.authorization.service;

import io.hohichh.marketplace.authorization.dto.*;
import io.hohichh.marketplace.authorization.exception.JwtAuthenticationException;
import io.hohichh.marketplace.authorization.exception.LoginAlreadyExistsException;
import io.hohichh.marketplace.authorization.mapper.UserCredentialsMapper;
import io.hohichh.marketplace.authorization.model.Role;
import io.hohichh.marketplace.authorization.model.RoleName;
import io.hohichh.marketplace.authorization.model.UserCredentials;
import io.hohichh.marketplace.authorization.repository.RoleRepository;
import io.hohichh.marketplace.authorization.repository.UserCredentialsRepository;
import io.hohichh.marketplace.authorization.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserCredentialsServiceImpl implements UserCredentialsService {

    private final RoleRepository roleRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final UserCredentialsMapper mapper;


    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtTokenProvider;

    @Override
    @Transactional
    public UserCredentialsResponseDto saveUserCredentials(
            UserCredentialsCreateDto createDto) {

        if (userCredentialsRepository.existsByLogin(createDto.getLogin())) {
            throw new LoginAlreadyExistsException("This login is already in use: "
                    + createDto.getLogin());
        }

        UserCredentials newUser = mapper.toEntity(createDto);

        Role newUserRole = roleRepository
                .findRoleByRoleName(RoleName.USER)
                .orElseThrow(() -> new RuntimeException("No '" + RoleName.USER + "' role in storage"));

        newUser.setRole(newUserRole);

        String hashedPassword = passwordEncoder.encode(createDto.getPassword());
        newUser.setPasswordHash(hashedPassword);
        UserCredentials savedUser = userCredentialsRepository.save(newUser);

        return mapper.toResponseDto(savedUser);
    }

    @Override
    @Transactional(readOnly = true)
    public LoginResponseDto login(LoginRequestDto loginDto) {
        UserCredentials user = userCredentialsRepository.findByLogin(loginDto.getLogin())
                .orElseThrow(() -> new JwtAuthenticationException("Wrong login or password"));

        boolean matches = passwordEncoder.matches(loginDto.getPassword(),
                user.getPasswordHash());

        if (!matches) {
            throw new JwtAuthenticationException("Wrong login or password");
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId(), user.getRole().getRoleName().name());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());

        return new LoginResponseDto(accessToken, refreshToken);
    }

    @Override
    @Transactional
    public LoginResponseDto refresh(RefreshTokenRequestDto refreshDto) {
        if (!jwtTokenProvider.validateRefreshToken(refreshDto.getRefreshToken())) {
            throw new JwtAuthenticationException("Refresh token is invalid or has expired");
        }

        UUID userId = jwtTokenProvider.getUserIdFromRefreshToken(refreshDto.getRefreshToken());

        UserCredentials user = userCredentialsRepository.findByUserId(userId)
                .orElseThrow(() -> new JwtAuthenticationException("User does not exist"));


        String newAccessToken = jwtTokenProvider.createAccessToken(user.getUserId(), user.getRole().getRoleName().name());
        String newRefreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());

        return new LoginResponseDto(newAccessToken, newRefreshToken);
    }
}