package io.hohichh.marketplace.authorization.repository;

import io.hohichh.marketplace.authorization.model.Role;
import io.hohichh.marketplace.authorization.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {
    Optional<Role> findRoleByRoleName(RoleName roleName);
}
