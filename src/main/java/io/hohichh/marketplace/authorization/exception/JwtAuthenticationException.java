package io.hohichh.marketplace.authorization.exception;

public class JwtAuthenticationException extends RuntimeException{

    public JwtAuthenticationException(String message){
        super(message);
    }
}
