package com.example.theworkersgateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(-1)
public class ExchangeFilter implements GlobalFilter {

    @Autowired
    private ExchangeProvider provider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        provider.set(exchange);

        return chain.filter(exchange)
                .doFinally(signal -> provider.clear());
    }
}
