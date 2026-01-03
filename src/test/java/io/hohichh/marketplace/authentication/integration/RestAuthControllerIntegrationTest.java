package io.hohichh.marketplace.authentication.integration;

import io.hohichh.marketplace.authentication.dto.*;
import io.hohichh.marketplace.authentication.exception.GlobalExceptionHandler;
import io.hohichh.marketplace.authentication.model.Role;
import io.hohichh.marketplace.authentication.model.RoleName;
import io.hohichh.marketplace.authentication.repository.RoleRepository;
import io.hohichh.marketplace.authentication.repository.UserCredentialsRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RestAuthControllerIntegrationTest extends AbstractApplicationTest {
	@Autowired
	private UserCredentialsRepository userCredentialsRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Value("${jwt.access-secret}")
	private String accessSecret;

	private static final String AUTH_URL = "/v1/auth";
	private static final String TEST_LOGIN = "testuser@example.com";
	private static final String TEST_PASSWORD = "Password123!";
	private static final UUID TEST_USER_ID = UUID.randomUUID();

	@BeforeEach
	 void setupDb() {
		Role adminRole = Role.builder().roleName(RoleName.ADMIN).build();
		Role userRole = Role.builder().roleName(RoleName.USER).build();
		roleRepository.saveAll(List.of(adminRole, userRole));
	}

	@AfterEach
	 void cleanup() {
		userCredentialsRepository.deleteAll();
		roleRepository.deleteAll();
	}

	@Test
	void saveUserCredentials_whenValid_shouldCreateCredentials() {
		UserCredentialsCreateDto createDto = new UserCredentialsCreateDto();
		createDto.setUserId(TEST_USER_ID);
		createDto.setLogin(TEST_LOGIN);
		createDto.setPassword(TEST_PASSWORD);

		ResponseEntity<UserCredentialsResponseDto> response = restTemplate.postForEntity(
				AUTH_URL + "/credentials",
				createDto,
				UserCredentialsResponseDto.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().getLogin()).isEqualTo(TEST_LOGIN);
		assertThat(response.getBody().getUserId()).isEqualTo(TEST_USER_ID);
		assertThat(response.getBody().getRoleName()).isEqualTo("USER");

		var savedInDb = userCredentialsRepository.findByLogin(TEST_LOGIN).get();
		assertThat(savedInDb.getPasswordHash()).isNotNull();
		assertThat(savedInDb.getPasswordHash()).isNotEqualTo(TEST_PASSWORD);
	}

	@Test
	void saveUserCredentials_whenLoginExists_shouldReturnConflict() {
		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		UserCredentialsCreateDto duplicateDto = new UserCredentialsCreateDto();
		duplicateDto.setUserId(UUID.randomUUID());
		duplicateDto.setLogin(TEST_LOGIN);
		duplicateDto.setPassword("another-pass");


		ResponseEntity<GlobalExceptionHandler.ErrorResponse> response = restTemplate.postForEntity(
				AUTH_URL + "/credentials",
				duplicateDto,
				GlobalExceptionHandler.ErrorResponse.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().message()).contains("This login is already in use");
	}

	@Test
	void deleteCredentials_whenOwner_shouldReturnNoContent() {
		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		String token = generateTestToken(TEST_USER_ID, "USER");

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(token);
		HttpEntity<Void> entity = new HttpEntity<>(headers);

		ResponseEntity<Void> response = restTemplate.exchange(
				AUTH_URL + "/credentials?user-id=" + TEST_USER_ID,
				HttpMethod.DELETE,
				entity,
				Void.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
		assertThat(userCredentialsRepository.findByUserId(TEST_USER_ID)).isEmpty();
	}

	@Test
	void deleteCredentials_whenNotOwner_shouldReturnForbidden() {
		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		UUID hackerId = UUID.randomUUID();
		String token = generateTestToken(hackerId, "USER");

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(token);
		HttpEntity<Void> entity = new HttpEntity<>(headers);


		ResponseEntity<String> response = restTemplate.exchange(
				AUTH_URL + "/credentials?user-id=" + TEST_USER_ID,
				HttpMethod.DELETE,
				entity,
				String.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(userCredentialsRepository.findByUserId(TEST_USER_ID)).isPresent();
	}

	@Test
	void deleteCredentials_whenNoToken_shouldReturnForbidden() {
		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		ResponseEntity<String> response = restTemplate.exchange(
				AUTH_URL + "/credentials?user-id=" + TEST_USER_ID,
				HttpMethod.DELETE,
				null,
				String.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	private String generateTestToken(UUID userId, String role) {
		SecretKey key = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
		Mockito.when(clock.instant()).thenReturn(Instant.now());
		Instant instant = clock.instant();
		return Jwts.builder()
				.subject(userId.toString())
				.claim("role", role)
				.issuedAt(Date.from(instant))
				.expiration(Date.from(instant.plusSeconds(3600)))
				.signWith(key)
				.compact();
	}

	@Test
	void login_whenValidCredentials_shouldReturnTokens() {
		Mockito.when(clock.instant()).thenReturn(Instant.now());

		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		LoginRequestDto loginDto = new LoginRequestDto();
		loginDto.setLogin(TEST_LOGIN);
		loginDto.setPassword(TEST_PASSWORD);

		ResponseEntity<LoginResponseDto> response = restTemplate.postForEntity(
				AUTH_URL + "/login",
				loginDto,
				LoginResponseDto.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().getAccessToken()).isNotBlank();
		assertThat(response.getBody().getRefreshToken()).isNotBlank();
	}

	@Test
	void login_whenInvalidPassword_shouldReturnUnauthorized() {
		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);

		LoginRequestDto loginDto = new LoginRequestDto();
		loginDto.setLogin(TEST_LOGIN);
		loginDto.setPassword("WRONG_PASSWORD");

		ResponseEntity<GlobalExceptionHandler.ErrorResponse> response = restTemplate.postForEntity(
				AUTH_URL + "/login",
				loginDto,
				GlobalExceptionHandler.ErrorResponse.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().message()).isEqualTo("Wrong login or password");
	}

	@Test
	void refresh_whenValidToken_shouldReturnNewTokens() {
		Instant time1 = Instant.parse("2025-11-06T10:00:00Z");
		Mockito.when(clock.instant()).thenReturn(time1);

		createUser(TEST_LOGIN, TEST_PASSWORD, TEST_USER_ID);
		LoginResponseDto oldTokens = loginUser(TEST_LOGIN, TEST_PASSWORD);

		RefreshTokenRequestDto refreshDto = new RefreshTokenRequestDto();
		refreshDto.setRefreshToken(oldTokens.getRefreshToken());

		Instant time2 = time1.plus(5, ChronoUnit.MINUTES);
		Mockito.when(clock.instant()).thenReturn(time2);

		ResponseEntity<LoginResponseDto> response = restTemplate.postForEntity(
				AUTH_URL + "/refresh",
				refreshDto,
				LoginResponseDto.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().getAccessToken()).isNotBlank();
		assertThat(response.getBody().getRefreshToken()).isNotBlank();
		assertThat(response.getBody().getAccessToken()).isNotEqualTo(oldTokens.getAccessToken());
		assertThat(response.getBody().getRefreshToken()).isNotEqualTo(oldTokens.getRefreshToken());
	}

	@Test
	void refresh_whenInvalidToken_shouldReturnUnauthorized() {
		RefreshTokenRequestDto refreshDto = new RefreshTokenRequestDto();
		refreshDto.setRefreshToken("not.a.real.token");

		ResponseEntity<GlobalExceptionHandler.ErrorResponse> response = restTemplate.postForEntity(
				AUTH_URL + "/refresh",
				refreshDto,
				GlobalExceptionHandler.ErrorResponse.class
		);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(response.getBody()).isNotNull();
		assertThat(response.getBody().message()).contains("Refresh token is invalid or has expired");
	}


	private void createUser(String login, String password, UUID userId) {
		UserCredentialsCreateDto createDto = new UserCredentialsCreateDto();
		createDto.setUserId(userId);
		createDto.setLogin(login);
		createDto.setPassword(password);
		restTemplate.postForEntity(AUTH_URL + "/credentials", createDto, UserCredentialsResponseDto.class);
	}


	private LoginResponseDto loginUser(String login, String password) {
		LoginRequestDto loginDto = new LoginRequestDto();
		loginDto.setLogin(login);
		loginDto.setPassword(password);

		ResponseEntity<LoginResponseDto> response = restTemplate.postForEntity(
				AUTH_URL + "/login",
				loginDto,
				LoginResponseDto.class
		);
		return response.getBody();
	}
}