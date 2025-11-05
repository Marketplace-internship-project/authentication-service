
package io.hohichh.marketplace.authorization.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
    private String login;
    private String password;
}