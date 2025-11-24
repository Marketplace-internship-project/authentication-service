package io.hohichh.marketplace.authentication.repository;

import io.hohichh.marketplace.authentication.model.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, UUID> {
    Optional<UserCredentials> findByUserId(UUID userId);
    Optional<UserCredentials> findByLogin(String login);
    boolean existsByLogin(String login);
    void deleteByUserId(UUID userId);
    boolean existsByUserId(UUID userId);
}
