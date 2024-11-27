package kopo.poly.config;

import kopo.poly.filter.JwtAuthenticationFilter;
import kopo.poly.handler.AccessDeniedHandler;
import kopo.poly.handler.LoginServerAuthenticationEncryptPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class SecurityConfig {

    private final AccessDeniedHandler accessDeniedHandler;

    private final LoginServerAuthenticationEncryptPoint loginServerAuthenticationEncryptPoint;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {

        log.info("인증, 인가 설정 시작");

        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.cors(ServerHttpSecurity.CorsSpec::disable);
        http.formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        http.exceptionHandling(exceptionHandlingSpec ->
                exceptionHandlingSpec.accessDeniedHandler(accessDeniedHandler));

        http.exceptionHandling(exceptionHandlingSpec ->
                exceptionHandlingSpec.authenticationEntryPoint(loginServerAuthenticationEncryptPoint));

        http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        http.authorizeExchange(authz -> authz
                .pathMatchers("/notice/**").hasAnyAuthority("ROLE_USER")
                .pathMatchers("/user/**").hasAnyAuthority("ROLE_USER")
                .pathMatchers("/login/**").permitAll()
                .pathMatchers("/reg/**").permitAll()
                .anyExchange().permitAll()
        );

        http.addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);

        log.info("인증 인가 종료 !");
        return http.build();
    }
}
