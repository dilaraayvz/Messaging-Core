package com.messaging.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;

    @Configuration
    public class BaseSecurityConfiguration {
        private final PasswordEncoder passwordEncoder;
        public BaseSecurityConfiguration(PasswordEncoder passwordEncoder){
            this.passwordEncoder = passwordEncoder;
        }
        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
            return authenticationConfiguration.getAuthenticationManager();
        }
    }

