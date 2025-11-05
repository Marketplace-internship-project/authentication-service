package io.hohichh.marketplace.authorization.exception;

public class LoginAlreadyExistsException extends RuntimeException{

    public LoginAlreadyExistsException(String message){
        super(message);
    }
}
