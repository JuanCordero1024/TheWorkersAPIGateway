package com.example.theworkersgateway;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class EccGenerator {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
            keyGen.initialize(ecSpec, new SecureRandom());

            KeyPair keyPair = keyGen.generateKeyPair();

            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            System.out.println("\n=== CLAVE PÚBLICA (Gateway) ===");
            System.out.println(publicKeyBase64);

            System.out.println("\n=== CLAVE PRIVADA (Backend) ===");
            System.out.println(privateKeyBase64);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}