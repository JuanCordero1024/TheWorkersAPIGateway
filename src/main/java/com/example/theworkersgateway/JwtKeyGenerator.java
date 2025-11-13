package com.example.theworkersgateway;

import javax.crypto.SecretKey;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Base64;

public class JwtKeyGenerator {
    public static void main(String[] args) {
        // Para HS384
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());

        System.out.println("Clave para HS512:");
        System.out.println(base64Key);
        System.out.println("Longitud en bits: " + (key.getEncoded().length * 8));
    }
}