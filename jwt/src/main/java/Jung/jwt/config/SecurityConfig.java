package Jung.jwt.config;

import Jung.jwt.jwt.JwtAccessDeniedHandler;
import Jung.jwt.jwt.JwtAuthenticationEntryPoint;
import Jung.jwt.jwt.JwtSecurityConfig;
import Jung.jwt.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  //Spring Security의 웹 보안 기능을 활성화 -> 모든 요청 URL이 스프링 시큐리티의 제어를 받도록 만듬
//@EnableMethodSecurity  //Spring Security의 메서드 수준 보안을 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final TokenProvider tokenProvider;  //jwt 토큰 생성, 토큰 유효성 검증 담당
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                //token을 사용하는 방식이기 때문에 csrf를 disable
                .csrf(AbstractHttpConfigurer::disable)

                //Exception 핸들링할 때 만들었던 클래스 추가
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                )

                //URL 기반 보안 규칙을 구성
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()
                        .anyRequest().authenticated()
                )

                //세션을 사용하지 않기 때문에 STATELESS로 설정
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //h2 콘솔 화면 깨지는 오류 해결
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))

                //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스 적용
//                .with(new JwtSecurityConfig(tokenProvider), customizer -> {})

                .build();
    }
}
