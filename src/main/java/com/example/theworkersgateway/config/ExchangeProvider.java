package com.example.theworkersgateway.config;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class ExchangeProvider {

    private static final ThreadLocal<ServerWebExchange> exchangeHolder = new ThreadLocal<>();

    public void set(ServerWebExchange exchange) {
        exchangeHolder.set(exchange);
    }

    public ServerWebExchange get() {
        return exchangeHolder.get();
    }

    public void clear() {
        exchangeHolder.remove();
    }
}
