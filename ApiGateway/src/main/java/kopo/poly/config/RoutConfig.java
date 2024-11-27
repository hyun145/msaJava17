package kopo.poly.config;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@RequiredArgsConstructor
@Configuration
public class RoutConfig {

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        return builder.routes().route(r -> r.path("/notice/**")
                .uri("lb://NOTICE-SERVICE:12000")
        ).route(r -> r.path("/user/**")
                .uri("lb://USER-SERVICE:11000")
        ).route(r -> r.path("/login/**")
                .uri("lb://USER-SERVICE:11000")
        ).route(r -> r.path("/reg/**")
                .uri("lb://USER-SERVICE:11000")
        ).build();
    }
}
