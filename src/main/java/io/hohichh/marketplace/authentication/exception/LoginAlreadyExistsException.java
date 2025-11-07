package io.hohichh.marketplace.authentication.exception;

public class LoginAlreadyExistsException extends RuntimeException{

    public LoginAlreadyExistsException(String message){
        super(message);
    }
}
