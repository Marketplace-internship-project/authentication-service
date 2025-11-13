package io.hohichh.marketplace.authentication;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

@SpringBootApplication
public class Application {

	@Bean
	public Clock clock() {
		return Clock.systemUTC();
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}
