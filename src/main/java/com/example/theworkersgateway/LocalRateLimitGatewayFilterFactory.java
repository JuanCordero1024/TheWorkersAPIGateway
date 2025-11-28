package com.example.theworkersgateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LocalRateLimitGatewayFilterFactory extends AbstractGatewayFilterFactory<LocalRateLimitGatewayFilterFactory.Config> {

    private final Map<String, RequestData> requestCounts = new ConcurrentHashMap<>();

    public LocalRateLimitGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            //Identificar al usuario (Por IP o por Header)
            String clientIp = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();

            // Obtener o crear datos de este usuario
            RequestData data = requestCounts.compute(clientIp, (key, val) -> {
                long now = System.currentTimeMillis();

                // Si es nuevo o ya pasó el tiempo de ventana (ej: 1 minuto), reseteamos
                if (val == null || (now - val.startTime > config.getDurationInMs())) {
                    return new RequestData(now, 1);
                }

                // Si está dentro del tiempo, aumentamos contador
                val.count++;
                return val;
            });

            // Verificar si se pasó del límite
            if (data.count > config.getMaxRequests()) {
                // Bloquear la petición
                exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                return exchange.getResponse().setComplete();
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {
        private int maxRequests;
        private long durationInMs;

        public int getMaxRequests() { return maxRequests; }
        public void setMaxRequests(int maxRequests) { this.maxRequests = maxRequests; }
        public long getDurationInMs() { return durationInMs; }
        public void setDurationInMs(long durationInMs) { this.durationInMs = durationInMs; }
    }

    private static class RequestData {
        long startTime;
        int count;

        public RequestData(long startTime, int count) {
            this.startTime = startTime;
            this.count = count;
        }
    }
}