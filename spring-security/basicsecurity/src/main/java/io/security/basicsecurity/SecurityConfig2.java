package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig2 {

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("1111")
                .roles("USER")
                .build();

        UserDetails sys = User.withDefaultPasswordEncoder()
                .username("sys")
                .password("1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("1111")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorizeRequest -> {
                    authorizeRequest
                            .requestMatchers("/login").permitAll()
                            .requestMatchers("/user").hasRole("USER")
                            .requestMatchers("/admin/pay").hasRole("ADMIN")
                            .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                            .anyRequest().authenticated();
                });

        http
                .formLogin(formLogin -> {
                    formLogin
                            .successHandler(new AuthenticationSuccessHandler() {
                                @Override
                                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                    RequestCache requestCache = new HttpSessionRequestCache();
                                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                                    String redirectUrl = savedRequest.getRedirectUrl();
                                    response.sendRedirect(redirectUrl);
                                }
                            });
                });

        http
                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling
                            .authenticationEntryPoint(new AuthenticationEntryPoint() {
                                @Override
                                public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                                    response.sendRedirect("/login");
                                }
                            })
                            .accessDeniedHandler(new AccessDeniedHandler() {
                                @Override
                                public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                                    response.sendRedirect("/denied");
                                }
                            })
                            ;
                });

        return http.build();
    }
}
