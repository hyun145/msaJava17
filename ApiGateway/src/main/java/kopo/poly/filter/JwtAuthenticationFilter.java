package kopo.poly.filter;


import kopo.poly.dto.TokenDTO;
import kopo.poly.jwt.JwtStatus;
import kopo.poly.jwt.JwtTokenProvider;
import kopo.poly.jwt.JwtTokenType;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    private final JwtTokenProvider jwtTokenProvider;


    private ResponseCookie deleteTokenCookie(String tokenName) {
        log.info("JWT 토큰 삭제 시작");

        log.info("tokenName : " + tokenName);

        ResponseCookie cookie = ResponseCookie.from(tokenName, "")
                .maxAge(0).build();

        return cookie;
    }

    private ResponseCookie createTokenCookie(String tokenName, long tokenValidTime, String token) {
        log.info("생성된 JWT 토큰 쿠키에 저장 ! ");

        log.info("tokenName : " + tokenName);
        log.info("token : " + token);

        ResponseCookie cookie = ResponseCookie.from(tokenName, token)
                .domain("localhost")
                .path("/")
                .maxAge(tokenValidTime)
                .httpOnly(true)
                .build();

        return cookie;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        log.info("필터 시작 !");

        log.info("request : " + request);
        log.info("request : " + request.getPath());

        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.ACCESS_TOKEN));

        log.info("accessToken : " + accessToken);

        JwtStatus accessTokenStatus = jwtTokenProvider.validateToken(accessToken);

        log.info("accessTokenStatus : " + accessTokenStatus);

        if (accessTokenStatus == JwtStatus.ACCESS) {

            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } else if (accessTokenStatus == JwtStatus.EXPIRED ||
                accessTokenStatus == JwtStatus.DENIED) {

            String refreshToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.REFRESH_TOKEN));

            JwtStatus refreshTokenStatus = jwtTokenProvider.validateToken(refreshToken);

            log.info("refreshTokenStatus : " + refreshTokenStatus);

            if (refreshTokenStatus == JwtStatus.ACCESS) {

                TokenDTO rDTO = Optional.ofNullable(jwtTokenProvider.getTokenInfo(refreshToken))
                        .orElseGet(() -> TokenDTO.builder().build());

                String userId = CmmUtil.nvl(rDTO.userId());
                String userRoles = CmmUtil.nvl(rDTO.role());

                log.info("refreshToken userID  : " + userId);
                log.info("refreshToken userRoles : " + userRoles);

                String reAccessToken = jwtTokenProvider.createToken(userId, userRoles);

                response.addCookie(this.deleteTokenCookie(accessTokenName));

                response.addCookie(this.createTokenCookie(accessTokenName, accessTokenValidTime, reAccessToken));

                Authentication authentication = jwtTokenProvider.getAuthentication(reAccessToken);

                return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        } else if (refreshTokenStatus == JwtStatus.EXPIRED) {
            log.info("Refresh Token 만료 - 스프링 시큐리티가 로그인 페이지로 이동 시킴");

        } else {
            log.info("Refresh Token 오류 - 스프링 시큐리티가 로그인 페이지로 이동시킴");
        }
    }
        log.info("필터 끝");


        return chain.filter(exchange);
    }
}
