package com.example.theworkersgateway;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

import java.security.Security;

@SpringBootApplication
@EnableFeignClients(basePackages = "com.example.theworkersgateway")
public class TheworkersGatewayApplication {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(TheworkersGatewayApplication.class, args);
    }

}
