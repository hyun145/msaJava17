package kopo.poly.jwt;



import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import kopo.poly.dto.TokenDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {


    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.token.creator}")
    private String creator;

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    public static final String HEADER_PREFIX = "Bearer ";

    public String createToken(String userId, String roles) {

        log.info("토큰 생성 Provider 시작 ! ");

        log.info("userID : " + userId);

        Claims claims = Jwts.claims()
                .setIssuer(creator)
                .setSubject(userId);

        claims.put("roles", roles);
        Date now = new Date();

        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + (accessTokenValidTime * 1000)))
                .signWith(secret, SignatureAlgorithm.HS256)
                .compact();
    }

    public TokenDTO getTokenInfo(String token) {
        log.info("토큰 가져오기 Provider 시작");

        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();

        String userId = CmmUtil.nvl(claims.getSubject());
        String role = CmmUtil.nvl((String) claims.get("roles"));

        log.info("userId : " + userId);

        log.info("role :"  + role);

        TokenDTO rDTO = TokenDTO.builder().userId(userId).role(role).build();

        return rDTO;

    }

    public Authentication getAuthentication(String token) {
        log.info("토큰에 저장된 정보 가져오기.");
        log.info("getAuthentication : " + token);

        TokenDTO rDTO = getTokenInfo(token);

        String userId = CmmUtil.nvl(rDTO.userId());

        String roles = CmmUtil.nvl(rDTO.role());

        log.info("user_ID : " + userId);

        log.info("roles : " + roles);

        Set<GrantedAuthority> pSet = new HashSet<>();

        if (roles.length() > 0) {
            for (String role : roles.split(",")) {
                pSet.add(new SimpleGrantedAuthority(role));
            }
        }

        log.info("토큰에 저장된 정보 가져오기 종료");

        return new UsernamePasswordAuthenticationToken(userId, "", pSet);
    }

    public String resolveToken(ServerHttpRequest request, JwtTokenType tokenType) {

        log.info("쿠키 및 Bearer 헤더에 저장된 Token 가져오기");

        String token = "";
        String tokenName = "";

        if (tokenType == JwtTokenType.ACCESS_TOKEN) {
            tokenName = accessTokenName;
        }else if(tokenType == JwtTokenType.REFRESH_TOKEN) {
            tokenName = refreshTokenName;

        }
        HttpCookie cookie = request.getCookies().getFirst(tokenName);

        if (cookie != null) {
            token = CmmUtil.nvl(cookie.getValue());
        }

        if (token.length() == 0) {
            String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);


            log.info("bearerToken : " + bearerToken);

            if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
                token = bearerToken.substring(7);
            }
            log.info("bearerToken token : " + token);

        }
        return token;
    }

    public JwtStatus validateToken(String token) {
        if (token.length() > 0) {
            try {
                SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

                Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();

                if (claims.getExpiration().before(new Date())) {
                    return JwtStatus.EXPIRED;
                } else {
                    return JwtStatus.ACCESS;
                }
            } catch (ExpiredJwtException e) {
                return JwtStatus.EXPIRED;
            } catch (JwtException | IllegalArgumentException e) {
                log.info("jwtException : {}", e);

                return JwtStatus.DENIED;
            }
        } else {
            return JwtStatus.DENIED;
        }
    }

}
