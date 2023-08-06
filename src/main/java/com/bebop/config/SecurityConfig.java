package com.bebop.config;

import org.apache.catalina.filters.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import com.filter.MyFilter1;
import com.filter.MyFilter2;

import lombok.RequiredArgsConstructor;

@Configuration // ioc
@EnableWebSecurity // 시큐리티 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // http.csrf().disable();
        // http.addFilter(new MyFilter1());
        // http.addFilter(new MyFilter2());
        // http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) // cors 정책에서 벗어나서 cross 요청이 와도 다 허용이 됨(인증이 필요하지 않은 요청에 한하여)
                                       // @CroosOrigin(인증없을때)/ 시큐리티 필터에 등록해야(인증있을때)
                .formLogin().disable()
                .httpBasic().disable() // httpBasic이란 Authorization에 id, pw달고 가는 방법
                // Bearer는 Token 달고 가는 방식으로 이 Bearer를 쓸 것이므로 httpBasic은 disable하는 것
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
        return http.build();

    }

}
