package io.security.corespringsecurity.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        String password = passwordEncoder().encode("1111");

        UserDetails user = User.withUsername("user")
                .password(password).roles("USER")
                .build();

        UserDetails manager = User.withUsername("manager")
                .password(password).roles("MANAGER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(password).roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authRequest -> {
                    authRequest
                            .requestMatchers("/").permitAll()
                            .requestMatchers("/mypage").hasRole("USER")
                            .requestMatchers("/messages").hasRole("MANAGER")
                            .requestMatchers("/config").hasRole("ADMIN")
                            .anyRequest().authenticated();
                })
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
