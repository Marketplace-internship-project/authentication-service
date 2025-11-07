package io.hohichh.marketplace.authentication.repository;

import io.hohichh.marketplace.authentication.model.Role;
import io.hohichh.marketplace.authentication.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findRoleByRoleName(RoleName roleName);
}
