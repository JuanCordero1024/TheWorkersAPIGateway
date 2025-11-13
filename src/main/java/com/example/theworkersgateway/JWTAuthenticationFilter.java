package com.example.theworkersgateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger; // Importar SLF4J
import org.slf4j.LoggerFactory; // Importar SLF4J
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.Date;

@Component
public class JWTAuthenticationFilter extends AbstractGatewayFilterFactory<JWTAuthenticationFilter.Config> {

    // 1. AÃ‘ADIR LOGGER
    private static final Logger log = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    @Value("${jwt.secret-key}")
    private String secretKey;

    private final Key signingKey;

    public JWTAuthenticationFilter(@Value("${jwt.secret-key}") String secretKey) {
        super(Config.class);
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Solicitud rechazada: No se encontrÃ³ encabezado Authorization o formato invÃ¡lido.");
                return this.onError(exchange, "No se proporcionó JWT o formato inválido", HttpStatus.UNAUTHORIZED);
            }

            final String token = authHeader.substring(7);

            try {
                Claims claims = this.validateToken(token);

                // 2. LOG DE TOKEN VIGENTE (Opcional, pero Ãºtil para ver la duraciÃ³n)
                long expirationTimeMs = claims.getExpiration().getTime();
                Date expirationDate = claims.getExpiration();

                log.info("Token [{}] Válido. Usuario: {}. Expira: {}",
                        token.substring(0, 15) + "...", claims.getSubject(), expirationDate);

                // 3. INYECTAR METADATA (ID de usuario)
                String userId = claims.getSubject();
                exchange.getRequest()
                        .mutate()
                        .header("X-Auth-User-Id", userId)
                        .build();

            } catch (ExpiredJwtException e) {
                // 4. LOG DE EXPIRACIÃ“N
                log.error("Token expirado para el usuario: {}. Solicitud rechazada.", e.getClaims().getSubject());
                return this.onError(exchange, "JWT ha expirado", HttpStatus.UNAUTHORIZED);
            } catch (SignatureException e) {
                log.error("Firma de JWT inválida. Token: {}. Solicitud rechazada.", token.substring(0, 15));
                return this.onError(exchange, "Firma de JWT inválida", HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                log.error("Error desconocido al validar el token. Causa: {}", e.getMessage());
                return this.onError(exchange, "Token JWT inválido", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    private Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(this.signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // --- MÃ©todo de Utilidad para Enviar la Respuesta 401 (sin cambios) ---
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String responseBody = String.format("{\"status\": \"%s\", \"message\": \"%s\"}",
                httpStatus.getReasonPhrase(), err);

        DataBufferFactory dataBufferFactory = response.bufferFactory();
        return response.writeWith(
                Mono.just(responseBody)
                        .map(s -> dataBufferFactory.wrap(s.getBytes()))
        );
    }

    public static class Config {

    }
}