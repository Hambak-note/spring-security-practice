package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {


//    @Autowired
//    private UserDetailsService userDetailsService;

     // AuthenticationManager 빈 참조 및 사용자정의 AuthenticationProvider 객체를 설정해야 할 경우
//    @Bean
//    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
//        authenticationManager.getProviders().add(customAuthenticationProvider());
//        return authenticationManager;
//    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }


    /**
     * 메모리 방식의 사용자 등록
     */
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.withUsername("user")
//                .password(password).roles("USER")
//                .build();
//
//        UserDetails manager = User.withUsername("manager")
//                .password(password).roles("MANAGER", "USER")
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password(password).roles("ADMIN", "USER", "MANAGER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, manager, admin);
//    }





    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 프로젝트 내의 css, js 등의 정적 리소스를 무시하기 위한 설정
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authRequest -> {
                    authRequest
                            .requestMatchers("/", "/users").permitAll()
                            .requestMatchers("/mypage").hasRole("USER")
                            .requestMatchers("/messages").hasRole("MANAGER")
                            .requestMatchers("/config").hasRole("ADMIN")
                            .anyRequest().authenticated();
                })
                .formLogin(formLogin -> {
                    formLogin
                            .loginPage("/login")
                            .loginProcessingUrl("/login_proc")
                            .defaultSuccessUrl("/")
                            .permitAll();
                });

        return http.build();
    }
}
