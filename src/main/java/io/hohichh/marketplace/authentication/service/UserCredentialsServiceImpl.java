/*
 * Author: Yelizaveta Verkovich aka Hohich
 * Task: Implement the core business logic for the Authorization Service,
 * handling credential storage, user login, and token management.
 */

package io.hohichh.marketplace.authentication.service;

import io.hohichh.marketplace.authentication.dto.*;
import io.hohichh.marketplace.authentication.exception.JwtAuthenticationException;
import io.hohichh.marketplace.authentication.exception.LoginAlreadyExistsException;
import io.hohichh.marketplace.authentication.exception.ResourceNotFoundException;
import io.hohichh.marketplace.authentication.model.Role;
import io.hohichh.marketplace.authentication.model.RoleName;
import io.hohichh.marketplace.authentication.model.UserCredentials;
import io.hohichh.marketplace.authentication.repository.RoleRepository;
import io.hohichh.marketplace.authentication.repository.UserCredentialsRepository;
import io.hohichh.marketplace.authentication.security.JwtProvider;
import io.hohichh.marketplace.authentication.mapper.UserCredentialsMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
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

    private static final Logger logger = LoggerFactory.getLogger(UserCredentialsServiceImpl.class);

    private static final String WRONG_LOGIN_INFO_MSG = "Wrong login or password";
    /**
     * Saves a new user's credentials, hashes the password, and assigns the default USER role.
     *
     * @param createDto DTO containing data for creating new credentials (userId, login, password).
     * @return A DTO representing the newly saved user credentials.
     * @throws LoginAlreadyExistsException if the login (email) is already in use.
     * @throws RuntimeException if the default 'USER' role is not found in the database.
     */
    @Override
    @Transactional
    public UserCredentialsResponseDto saveUserCredentials(
            UserCredentialsCreateDto createDto) {
        logger.debug("Attempting to save user credentials");

        if (userCredentialsRepository.existsByLogin(createDto.getLogin())) {
            logger.error("Error: login is already in use");
            throw new LoginAlreadyExistsException("This login is already in use: "
                    + createDto.getLogin());
        }

        UserCredentials newUser = mapper.toEntity(createDto);

        Role newUserRole = roleRepository
                .findRoleByRoleName(RoleName.USER)
                .orElseThrow(() -> {
                            logger.error("Error: Unable to find {} role in database", RoleName.USER);
                            return new ResourceNotFoundException("No '" + RoleName.USER + "' role in storage");
                        }
                );

        newUser.setRole(newUserRole);

        String hashedPassword = passwordEncoder.encode(createDto.getPassword());
        newUser.setPasswordHash(hashedPassword);
        UserCredentials savedUser = userCredentialsRepository.save(newUser);

        logger.info("Successfully register new user");
        return mapper.toResponseDto(savedUser);
    }

    @Override
    @Transactional
    @PreAuthorize("#userId.toString() == authentication.name")
    public void deleteUserCredentialsByUserId(UUID userId){
        logger.debug("Attempting to delete user credentials");

        if (userCredentialsRepository.existsByUserId(userId)) {
            userCredentialsRepository.deleteByUserId(userId);
        } else{
            logger.error("Error: Unable to delete user credentials with id {}", userId);
            throw new ResourceNotFoundException("No credentials with user id " + userId);
        }

        logger.info("Successfully deleted user credentials");
    }

    /**
     * Validates user credentials and generates JWT tokens upon successful authentication.
     *
     * @param loginDto DTO containing the user's login and password.
     * @return A DTO containing a new access and refresh token pair.
     * @throws JwtAuthenticationException if the login is incorrect or the password does not match.
     */
    @Override
    @Transactional(readOnly = true)
    public LoginResponseDto login(LoginRequestDto loginDto) {
        logger.debug("Attempting to login user");
        UserCredentials user = userCredentialsRepository.findByLogin(loginDto.getLogin())
                .orElseThrow(() -> {
                    logger.error(WRONG_LOGIN_INFO_MSG);
                    return new JwtAuthenticationException(WRONG_LOGIN_INFO_MSG);
                });

        boolean matches = passwordEncoder.matches(loginDto.getPassword(),
                user.getPasswordHash());

        if (!matches) {
            logger.error(WRONG_LOGIN_INFO_MSG);
            throw new JwtAuthenticationException(WRONG_LOGIN_INFO_MSG);
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId(), user.getRole().getRoleName().name());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());

        logger.info("Successfully login user");
        return new LoginResponseDto(accessToken, refreshToken);
    }

    /**
     * Validates a refresh token and issues a new pair of tokens.
     *
     * @param refreshDto DTO containing the user's valid refresh token.
     * @return A new DTO containing a regenerated access and refresh token pair.
     * @throws JwtAuthenticationException if the refresh token is invalid, expired,
     * or the associated user does not exist.
     */
    @Override
    @Transactional
    public LoginResponseDto refresh(RefreshTokenRequestDto refreshDto) {
        logger.debug("Attempting to refresh tokens");
        if (!jwtTokenProvider.validateRefreshToken(refreshDto.getRefreshToken())) {
            throw new JwtAuthenticationException("Refresh token is invalid or has expired");
        }

        UUID userId = jwtTokenProvider.getUserIdFromRefreshToken(refreshDto.getRefreshToken());

        UserCredentials user = userCredentialsRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    logger.error("User does not exist");
                    return new JwtAuthenticationException("User does not exist");
                });

        String newAccessToken = jwtTokenProvider.createAccessToken(user.getUserId(), user.getRole().getRoleName().name());
        String newRefreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());

        logger.info("Successfully refresh tokens");
        return new LoginResponseDto(newAccessToken, newRefreshToken);
    }
}