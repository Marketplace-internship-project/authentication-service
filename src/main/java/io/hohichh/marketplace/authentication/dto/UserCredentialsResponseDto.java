package io.hohichh.marketplace.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import java.util.UUID;

@Data
public class UserCredentialsResponseDto {
    @NotNull
    private UUID id;

    @NotNull
    private UUID userId;

    @NotBlank
    private String login;

    @NotBlank
    private String roleName;
}