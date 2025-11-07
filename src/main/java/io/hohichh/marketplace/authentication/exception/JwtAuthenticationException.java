package io.hohichh.marketplace.authentication.exception;

public class JwtAuthenticationException extends RuntimeException{

    public JwtAuthenticationException(String message){
        super(message);
    }
}
