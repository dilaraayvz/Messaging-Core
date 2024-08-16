package com.messaging.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.*;
//@Component // sonradan eklendi.
@Service
public class BaseJwtService {
    private long EXPIRATION = 600000;
    private String SECRET_KEY = "s6Q3mMkWa3vDHEIYO4fKlEXA+JO1pYXEMUGfG0zNAAwp2sCgacB6hYT1umS7qRIstYbgFT0anGjIuCTOD+8ai61M5o3W7Bbq0JRjAM4zmpvkqxaku0o1nD9phonZe2GUyFZHJO46TlsHWMmS0bwaGSEYd0HqYu6Il9b9vYR2ziCmYZz9Ihul8deSs+Fubq4m4PBRxG5OG4C5dNAM6Lce6ERe3gBnHYQ7KwsNNyjfEo+xHxlRO7K/HL3Krie9OSadwH2dD9vCvloibkvd37emGKbaFvsmE8bomTwmaE+yXPpIxkZUYzC8bLssHFVVkEhKkcdeWZ++3mVKHLWhL3yCL3yd2Y3FGPsnJcbhwhQFdus=";

    public String generateToken(String username, Map<String, Object> extraClaims) {
        String token = Jwts
                .builder()
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                .claims(extraClaims)
                .signWith(getSigningKey())
                .compact();
        return token;
    }

    public String generateTokenWithClaims(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(userDetails.getUsername(), claims);
    }

    public Boolean validateToken(String token) {
        return getTokenClaims(token).getExpiration().after(new Date()); // Kendi ürettiğim token mı?
    }

    public String extractUsername(String token) {
        return getTokenClaims(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        return Collections.emptyList();
    }
    private Claims getTokenClaims(String token) {
        return Jwts
                .parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}