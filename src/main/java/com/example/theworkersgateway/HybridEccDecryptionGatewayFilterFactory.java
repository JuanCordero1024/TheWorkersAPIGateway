package com.example.theworkersgateway;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import lombok.Data;

@Component
public class HybridEccDecryptionGatewayFilterFactory
        extends AbstractGatewayFilterFactory<HybridEccDecryptionGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(HybridEccDecryptionGatewayFilterFactory.class);

    private static final String ALGORITHM_AES = "AES/GCM/NoPadding";
    private static final String ALGORITHM_ECC = "ECIES";
    private static final int GCM_IV_LENGTH = 12;

    private final PrivateKey eccPrivateKey;
    private final ModifyRequestBodyGatewayFilterFactory modifyRequestBodyFilter;

    // Registra BouncyCastle una vez
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // DTO para parsear el JSON de la petición
    @Data
    private static class EncryptedPayload {
        private String encryptedKey;
        private String encryptedData;
        private String iv;
    }

    public HybridEccDecryptionGatewayFilterFactory(
            @Value("${backend-ecc-private-key}") String eccPrivateKeyBase64,
            ModifyRequestBodyGatewayFilterFactory modifyRequestBodyFilter) throws Exception {
        super(Config.class);
        this.eccPrivateKey = loadEccPrivateKey(eccPrivateKeyBase64);
        this.modifyRequestBodyFilter = modifyRequestBodyFilter;
        log.info("Clave privada ECC cargada exitosamente.");
    }

    @Override
    public GatewayFilter apply(Config config) {
        log.info("Registrando filtro de descifrado híbrido");
        return modifyRequestBodyFilter.apply(c -> {
            c.setInClass(EncryptedPayload.class);
            c.setOutClass(String.class);
            c.setRewriteFunction(EncryptedPayload.class, String.class, new DecryptionRewriteFunction());
        });
    }

    private class DecryptionRewriteFunction implements RewriteFunction<EncryptedPayload, String> {

        @Override
        public Mono<String> apply(ServerWebExchange exchange, EncryptedPayload payload) {
            try {
                log.info("Descifrando petición para: {}", exchange.getRequest().getPath());

                // 1. Descifrar clave AES con ECC (usando clave privada)
                SecretKey aesKey = decryptWithEcc(payload.getEncryptedKey(), eccPrivateKey);

                // 2. Descifrar datos con AES
                String decryptedBody = decryptWithAes(
                        payload.getEncryptedData(),
                        aesKey,
                        Base64.getDecoder().decode(payload.getIv())
                );

                log.info("Descifrado completado, enviando body original al microservicio.");
                return Mono.just(decryptedBody);

            } catch (Exception e) {
                log.error("Error durante el descifrado híbrido: ", e);
                // Falla la petición si no se puede descifrar
                return Mono.error(new RuntimeException("No se pudo descifrar la petición: ", e));
            }
        }
    }

    // --- Métodos de Descifrado ---

    private SecretKey decryptWithEcc(String encryptedKeyBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_ECC, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKeyBase64));
        // Reconstruye la SecretKey de AES
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    private String decryptWithAes(String encryptedDataBase64, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedDataBase64));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Carga la clave privada (Formato PKCS8)
    private PrivateKey loadEccPrivateKey(String base64PrivateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(spec);
    }

    public static class Config {}
}