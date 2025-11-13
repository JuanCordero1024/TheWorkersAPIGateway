package com.example.theworkersgateway;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class HybridEccEncryptionGatewayFilterFactory
        extends AbstractGatewayFilterFactory<HybridEccEncryptionGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(HybridEccEncryptionGatewayFilterFactory.class);

    private final PublicKey eccPublicKey;
    private final ModifyResponseBodyGatewayFilterFactory modifyResponseBodyFilter;

    private static final String ALGORITHM_AES = "AES/GCM/NoPadding";
    private static final String ALGORITHM_ECC = "ECIES";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;

    public HybridEccEncryptionGatewayFilterFactory(
            @Value("${backend-ecc-public-key}") String eccPublicKeyBase64,
            ModifyResponseBodyGatewayFilterFactory modifyResponseBodyFilter) throws Exception {
        super(Config.class);
        this.eccPublicKey = loadEccPublicKey(eccPublicKeyBase64);
        this.modifyResponseBodyFilter = modifyResponseBodyFilter;
        log.info("✅ Clave pública ECC cargada exitosamente.");
    }

    @Override
    public GatewayFilter apply(Config config) {
        log.info("🔐 Registrando filtro de cifrado híbrido");

        return modifyResponseBodyFilter.apply(c -> {
            c.setRewriteFunction(String.class, String.class, new EncryptionRewriteFunction());
        });
    }

    private class EncryptionRewriteFunction implements RewriteFunction<String, String> {

        @Override
        public Mono<String> apply(ServerWebExchange exchange, String body) {
            try {
                log.info("🔒 Cifrando respuesta para: {}", exchange.getRequest().getPath());
                log.info("📄 Body original ({} chars): {}",
                        body.length(),
                        body.length() > 100 ? body.substring(0, 100) + "..." : body);

                if (body == null || body.isEmpty()) {
                    log.warn("⚠️ Body vacío, no se cifrará");
                    return Mono.just(body);
                }

                // Generar clave AES y IV
                SecretKey aesKey = generateAesKey();
                byte[] iv = generateIv();

                // Cifrar datos con AES
                String encryptedData = encryptWithAes(body, aesKey, iv);

                // Cifrar clave AES con ECC
                String encryptedAesKey = encryptWithEcc(aesKey.getEncoded(), eccPublicKey);

                // Construir respuesta cifrada
                String finalResponseBody = String.format(
                        "{\"encryptedKey\":\"%s\",\"encryptedData\":\"%s\",\"iv\":\"%s\"}",
                        encryptedAesKey,
                        encryptedData,
                        Base64.getEncoder().encodeToString(iv)
                );

                log.info("✅ Cifrado completado: {} chars → {} chars", body.length(), finalResponseBody.length());

                return Mono.just(finalResponseBody);

            } catch (Exception e) {
                log.error("❌ Error durante el cifrado híbrido", e);
                return Mono.just(body); // En caso de error, devolver original
            }
        }
    }

    private SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    private byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private String encryptWithAes(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String encryptWithEcc(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM_ECC, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private PublicKey loadEccPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(spec);
    }

    public static class Config {}
}