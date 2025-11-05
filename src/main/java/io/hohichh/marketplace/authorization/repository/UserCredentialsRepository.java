package io.hohichh.marketplace.authorization.repository;

import io.hohichh.marketplace.authorization.model.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, UUID> {
    Optional<UserCredentials> findByUserId(UUID userId);
    Optional<UserCredentials> findByLogin(String login);
    boolean existsByLogin(String login);
}
