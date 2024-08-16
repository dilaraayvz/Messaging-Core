package com.messaging.services;

import com.messaging.security.BaseJwtFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;

@Service
public class BaseSecurityService {
    private final BaseJwtFilter jwtFilter;
    public BaseSecurityService(BaseJwtFilter jwtFilter){
        this.jwtFilter = jwtFilter;
    }
    public void configureCoreSecurity(HttpSecurity httpSecurity) throws Exception
    {
        httpSecurity
                .csrf(csrf -> csrf.disable())  // Yeni API kullanılarak CSRF korumasını devre dışı bırakır
                .httpBasic(httpBasic -> httpBasic.disable())  // Yeni API kullanılarak HTTP Basic doğrulamayı devre dışı bırakır
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);  // JWT filter'ını ekler
    }
}