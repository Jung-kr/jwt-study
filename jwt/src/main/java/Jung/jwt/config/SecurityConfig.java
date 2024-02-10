package Jung.jwt.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  //Spring Security의 웹 보안 기능을 활성화 -> 모든 요청 URL이 스프링 시큐리티의 제어를 받도록 만듬
//@EnableMethodSecurity  //Spring Security의 메서드 수준 보안을 활성화
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)  //token을 사용하는 방식이기 때문에 csrf를 disable로
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  //세션을 사용하지 않기 때문에 STATELESS로 설정
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))  //h2 콘솔 화면 깨지는 오류 해결
                .authorizeHttpRequests(authz -> authz  //URL 기반 보안 규칙을 구성
                        .requestMatchers("/api/hello").permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()
                        .anyRequest().authenticated()
                )
                .build();
    }
}
