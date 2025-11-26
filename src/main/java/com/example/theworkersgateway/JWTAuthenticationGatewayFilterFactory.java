package com.example.theworkersgateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;

@Component
public class JWTAuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<JWTAuthenticationGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(JWTAuthenticationGatewayFilterFactory.class);
    private final SecretKey key;

    public JWTAuthenticationGatewayFilterFactory(@Value("${jwt.secret-key}") String secretKey) {
        super(Config.class);
        try {
            byte[] keyBytes = Base64.getDecoder().decode(secretKey);
            this.key = Keys.hmacShaKeyFor(keyBytes);
            log.info("Clave JWT cargada correctamente. Longitud: {} bits", keyBytes.length * 8);
        } catch (Exception e) {
            log.error("Error al cargar la clave JWT", e);
            throw new IllegalStateException("No se pudo cargar la clave JWT", e);
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.info("JWTAuthentication ejecutándose para: {}", exchange.getRequest().getPath());

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Token JWT no encontrado o formato incorrecto");
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            try {
                Claims claims = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();

                log.info("Token válido para usuario: {}", claims.getSubject());

                return chain.filter(exchange);

            } catch (io.jsonwebtoken.ExpiredJwtException e) {
                log.error("Token expirado: ", e);
                return onError(exchange, HttpStatus.UNAUTHORIZED);

            } catch (io.jsonwebtoken.security.SignatureException e) {
                log.error("Firma del token inválida: ", e);
                return onError(exchange, HttpStatus.UNAUTHORIZED);

            } catch (io.jsonwebtoken.MalformedJwtException e) {
                log.error("Token malformado: ", e);
                return onError(exchange, HttpStatus.UNAUTHORIZED);

            } catch (Exception e) {
                log.error("Error desconocido al validar el token: ", e);
                return onError(exchange, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {}
}