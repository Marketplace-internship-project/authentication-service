
package io.hohichh.marketplace.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequestDto {
    @NotBlank
    private String login;

    @NotBlank
    private String password;
}