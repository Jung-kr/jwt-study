package Jung.jwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

//JWT 토큰 생성, 토큰 유효성 검증 담당
@Slf4j
@Component
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;  //시크릿 키
    private final Long jwtTokenValidTime;  //토큰 만료 시간
    private Key key;

    public TokenProvider(@Value("${jwt.secret}") String secret,
                         @Value("${jwt.token-validity-in-seconds}") Long jwtTokenValidTime) {
        this.secret = secret;
        this.jwtTokenValidTime = jwtTokenValidTime;
    }

    @Override
    public void afterPropertiesSet() throws Exception {  //의존관계 주입 종료 후 호출(secret 때문)
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Authentication 객체의 권한 정보를 이용해서 jwt 토큰을 생성하는 메서드
     */
    public String createToken(Authentication authentication) {

        String authorities = authentication.getAuthorities().stream()  //Authentication 객체와 연결된 사용자에게 부여된 권한을 검색
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.jwtTokenValidTime);  //token의 유효기간 계산

        return Jwts.builder()
                .setSubject(authentication.getName())  //jwt 제목 설정
                .claim(AUTHORITIES_KEY, authorities)  //jwt에 사용자와 관련된 권한 저장
                .signWith(key, SignatureAlgorithm.HS512)  //key와 서명 알고리즘을 이용하여 jwt에 서명
                .setExpiration(validity)  //jwt 만료 시간 설정
                .compact();  //jwt 최종 문자열 표현 압축
    }

    /**
     * (역으로) Token에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메서드
     */
    //(역으로) Token에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메서드
    public Authentication getAuthentication(String token) {

        //지정된 key를 사용하여 jwt 토큰을 구문 분석 -> 클레임으로 추출
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /**
     * 토큰의 유효성 검증 수행
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.error("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }
}
