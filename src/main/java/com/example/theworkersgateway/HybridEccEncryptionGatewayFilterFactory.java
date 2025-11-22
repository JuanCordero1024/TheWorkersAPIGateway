package com.example.theworkersgateway;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

@Component
public class HybridEccEncryptionGatewayFilterFactory
        extends AbstractGatewayFilterFactory<HybridEccEncryptionGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(HybridEccEncryptionGatewayFilterFactory.class);

    private final ModifyResponseBodyGatewayFilterFactory modifyResponseBodyFilter;

    private static final String ALGORITHM_AES = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int ECIES_IV_LENGTH = 16;

    public HybridEccEncryptionGatewayFilterFactory(
            ModifyResponseBodyGatewayFilterFactory modifyResponseBodyFilter) {
        super(Config.class);
        this.modifyResponseBodyFilter = modifyResponseBodyFilter;
        // Aseguramos que BC esté registrado
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        log.info("Filtro de Cifrado Híbrido (Encryption) con HKDF-SHA256 cargado.");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return modifyResponseBodyFilter.apply(c -> {
            c.setRewriteFunction(String.class, String.class, new EncryptionRewriteFunction());
        });
    }

    private class EncryptionRewriteFunction implements RewriteFunction<String, String> {

        @Override
        public Mono<String> apply(ServerWebExchange exchange, String body) {
            try {
                if (!exchange.getResponse().getStatusCode().is2xxSuccessful() || body == null || body.isEmpty()) {
                    return Mono.just(body);
                }

                log.info("Cifrando respuesta para: {}", exchange.getRequest().getPath());

                // 1. Generar clave AES y IV para los DATOS
                SecretKey aesKey = generateAesKey();
                byte[] iv = generateIv(GCM_IV_LENGTH);

                // 2. Cifrar el cuerpo (JSON) con AES
                String encryptedData = encryptWithAes(body, aesKey, iv);

                // 3. Obtener la clave pública del CLIENTE desde el contexto (puesta por JWT Filter)
                String clientKeyBase64 = exchange.getAttribute("clientEccKey");

                if (clientKeyBase64 == null || clientKeyBase64.isEmpty()) {
                    log.error("No se encontró 'clientEccKey' en el contexto.");
                    throw new RuntimeException("Clave de cifrado de cliente no encontrada");
                }

                PublicKey clientEccPublicKey = loadEccPublicKey(clientKeyBase64);

                // 4. Cifrar la clave AES usando ECIES (Compatible con eciesjs: HKDF-SHA256)
                String encryptedAesKey = encryptWithEcc(aesKey.getEncoded(), clientEccPublicKey);

                // 5. Construir respuesta JSON final
                String finalResponseBody = String.format(
                        "{\"encryptedKey\":\"%s\",\"encryptedData\":\"%s\",\"iv\":\"%s\"}",
                        encryptedAesKey,
                        encryptedData,
                        Base64.getEncoder().encodeToString(iv)
                );

                return Mono.just(finalResponseBody);

            } catch (Exception e) {
                log.error("Error durante el cifrado híbrido: ", e);
                return Mono.just(body);
            }
        }
    }

    // --- Lógica ECIES corregida para eciesjs ---
    private String encryptWithEcc(byte[] dataToEncrypt, PublicKey clientPublicKey) throws Exception {

        // A. Setup de parámetros y claves
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(spec, new SecureRandom());

        // Generar par efímero
        KeyPair ephemeralKeyPair = keyGen.generateKeyPair();
        ECPublicKey ephemeralPub = (ECPublicKey) ephemeralKeyPair.getPublic();
        ECPrivateKey ephemeralPriv = (ECPrivateKey) ephemeralKeyPair.getPrivate();

        ECPublicKey clientEC = (ECPublicKey) clientPublicKey;

        // B. Calcular el Secreto Compartido (Punto Q = d * Q_cliente)
        // Usamos multiplicación directa de curvas para mayor control que KeyAgreement
        BigInteger dEphemeral = ephemeralPriv.getD();
        ECPoint sharedPoint = clientEC.getQ().multiply(dEphemeral).normalize();

        // C. Obtener coordenada X (IKM para HKDF) - 32 bytes
        byte[] sharedX = sharedPoint.getAffineXCoord().getEncoded();

        // D. Preparar 'info' para HKDF: EphemeralPub(Uncompressed) || ClientPub(Uncompressed)
        // eciesjs usa claves NO comprimidas (65 bytes) para el cálculo del hash por defecto. AMBOS DE 65 Bytes
        byte[] ephemPubBytes = ephemeralPub.getQ().getEncoded(false);
        byte[] clientPubBytes = clientEC.getQ().getEncoded(false);

        ByteArrayOutputStream infoOut = new ByteArrayOutputStream();
        infoOut.write(ephemPubBytes);
        infoOut.write(clientPubBytes);
        byte[] hkdfInfo = infoOut.toByteArray();

        // E. Derivar clave AES usando HKDF-SHA256
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedX, null, hkdfInfo));

        // AES-256
        byte[] derivedAesKey = new byte[32];
        hkdf.generateBytes(derivedAesKey, 0, derivedAesKey.length);

        String derivedHex = bytesToHex(derivedAesKey);
        String derivedB64 = Base64.getEncoder().encodeToString(derivedAesKey);
        log.info("DEBUG HKDF AES KEY (hex): {}", derivedHex);
        log.info("DEBUG HKDF AES KEY (b64): {}", derivedB64);
        // F. Cifrar la "dataToEncrypt" (que es la clave AES del body) usando la clave derivada
        byte[] iv = generateIv(ECIES_IV_LENGTH);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivedAesKey, "AES"), gcmSpec);

        byte[] ciphertext = cipher.doFinal(dataToEncrypt);

        // G. Empaquetar: [EphemPubKey (65 bytes)] + [IV (16 bytes)] + [Ciphertext]
        ByteArrayOutputStream finalOutput = new ByteArrayOutputStream();
        finalOutput.write(ephemPubBytes);
        finalOutput.write(iv);
        finalOutput.write(ciphertext);

        return Base64.getEncoder().encodeToString(finalOutput.toByteArray());
    }

    // --- Métodos Auxiliares ---

    private SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    private byte[] generateIv(int length) {
        byte[] iv = new byte[length];
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

    private PublicKey loadEccPublicKey(String publicKeyHex) throws Exception {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);

        // Hex comprimido → bytes (sin BigInteger)
        byte[] keyBytes = hexStringToByteArray(publicKeyHex);

        ECPoint point = spec.getCurve().decodePoint(keyBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);
        return kf.generatePublic(pubSpec);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static class Config {}
}