package com.example.login_auth_api.infra.security;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.login_auth_api.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secretKey;
    public String generate(User user){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            String token = JWT.create().withIssuer("login-auth-api").
                    withSubject(user.getEmail()).
                    withExpiresAt(this.generateHour()).
                    sign(algorithm);
            return token;
        } catch (JWTCreationException e){
            throw new RuntimeException("Error while authenticating");
        }
    }

    public String validateToken(String token){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            return JWT.require(algorithm).
                    withIssuer("login-auth-api").
                    build().
                    verify(token).
                    getSubject();
        } catch (JWTVerificationException e){
            return null;
        }


    }

    private Instant generateHour(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-00:03"));
    }
}
