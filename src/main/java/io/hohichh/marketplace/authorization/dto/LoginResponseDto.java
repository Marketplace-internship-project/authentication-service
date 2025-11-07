
package io.hohichh.marketplace.authorization.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponseDto {
    @NotBlank
    private String accessToken;

    @NotBlank
    private String refreshToken;
}