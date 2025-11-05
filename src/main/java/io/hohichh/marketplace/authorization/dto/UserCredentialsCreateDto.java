
package io.hohichh.marketplace.authorization.dto;

import lombok.Data;
import java.util.UUID;

@Data
public class UserCredentialsCreateDto {
    private UUID userId;
    private String login;
    private String password;
}