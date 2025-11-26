package com.example.theworkersgateway.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.ServerWebExchange;

@Configuration
public class FeignClientInterceptor implements RequestInterceptor {

    @Autowired
    private ExchangeProvider provider;

    @Override
    public void apply(RequestTemplate template) {

        ServerWebExchange exchange = provider.get();

        if (exchange == null) {
            return;
        }

        String token = exchange.getAttribute("jwtToken");

        if (token != null) {
            template.header("Authorization", "Bearer " + token);
        }
    }
}
