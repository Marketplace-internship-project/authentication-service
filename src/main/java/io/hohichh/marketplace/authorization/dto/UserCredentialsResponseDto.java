package io.hohichh.marketplace.authorization.dto;

import lombok.Data;
import java.util.UUID;

@Data
public class UserCredentialsResponseDto {
    private UUID id;
    private UUID userId;
    private String login;
    private String roleName;
}