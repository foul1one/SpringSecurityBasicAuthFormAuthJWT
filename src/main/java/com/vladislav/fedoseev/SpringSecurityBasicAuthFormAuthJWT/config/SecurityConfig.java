package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.config;

import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // помечаем что класс является конфигурационным
@EnableWebSecurity // включаем web security
public class SecurityConfig {

    // начиная с версси секьюрити 5.7.0 конфигурация осуществляется не через наследование класса WebSecurityConfigurerAdapter
    // а через создание бина SecurityFilterChain, в котором мы настраиваем HttpSecurity
    // в HttpSecurity мы можем настроить какой вид авторизации мы будем использовать, какие енд поинты у нас открыты, какие закрыты,
    // указать пользователи с какими ролями могут иметь доступ к определенному енд поинту и т.д.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // отключаем csrf
                .authorizeHttpRequests() // начинаем настройку запросов, которые требуют авторизации
                .requestMatchers("/").permitAll() // к корню проекта доступ имеют все и пользователи и не пользователи
                // ко всем GET запросам по адресу, который начинается с "/api", имеют доступ юзеры со следующими ролями
                .requestMatchers(HttpMethod.GET, "/api/**").hasAnyRole(Role.ADMIN.name(), Role.USER.name())
                // К POST и DELETE запросам, которые начинаются с "/api", доступ имеет только юзер с ролью админ
                .requestMatchers(HttpMethod.POST, "/api/**").hasRole(Role.ADMIN.name())
                .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole(Role.ADMIN.name())
                .anyRequest() // каждый запросы
                .authenticated() // должен быть аутентифицирован
                .and()
                .httpBasic(); // аутентификация через http basic
        return http.build();
    }

    // Здесь мы создаем бин UserDetailsService, с помощью данного бина я получаю доступ к хранилищу юзеров
    // В данном случае я буду хранить юзеров в памяти приложения, то есть In Memory
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin")) // здесь мы шифруем наш пароль через BCrypt
                        .roles(Role.ADMIN.name())
                        .build(),
                User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user"))
                        .roles(Role.USER.name())
                        .build()
        );
    }

    // Этот бин отвечает за кодировку пароля по алгоритму BCrypt
    // Декодировать защированную этим алгоритмом строку практически невозможно
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
