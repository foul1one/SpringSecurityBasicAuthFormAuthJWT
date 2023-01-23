package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.config;

import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.security.JwtConfigurer;
import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.security.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // помечаем что класс является конфигурационным
@EnableWebSecurity // включаем web security
@EnableMethodSecurity
// чтобы права доступа работали в контролере через аннотаицю @PreAuthorize, нужно добавить эту аннотацию
public class SecurityConfig {

    private final JwtConfigurer jwtConfigurer;
    private final UserDetailsServiceImpl userDetailsService;
    public SecurityConfig (JwtConfigurer jwtConfigurer, UserDetailsServiceImpl userDetailsService) {
        this.jwtConfigurer = jwtConfigurer;
        this.userDetailsService = userDetailsService;
    }

    // начиная с версси секьюрити 5.7.0 конфигурация осуществляется не через наследование класса WebSecurityConfigurerAdapter
    // а через создание бина SecurityFilterChain, в котором мы настраиваем HttpSecurity
    // в HttpSecurity мы можем настроить какой вид авторизации мы будем использовать, какие енд поинты у нас открыты, какие закрыты,
    // указать пользователи с какими ролями или правами доступа могут иметь доступ к определенному енд поинту и т.д.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // отключаем csrf
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // отключаем сессии
                .and()
                .authorizeHttpRequests() // начинаем настройку запросов, которые требуют авторизации
                .requestMatchers("/").permitAll() // к корню проекта доступ имеют все и пользователи и не пользователи системы
                .requestMatchers("/api/v1/auth/login").permitAll()
                .anyRequest() // каждый запрос
                .authenticated() // должен быть аутентифицирован
                .and()
                .apply(jwtConfigurer); // применяем настройки которые прописаны в этом jwtConfigurer
        return http.build();
    }

    // Этот бин отвечает за кодировку пароля по алгоритму BCrypt
    // Декодировать защированную этим алгоритмом строку практически невозможно
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    // Создаем бин AuthenticationManager
    @Bean
    public AuthenticationManager daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(); // создали класс поставщика данных с БД и работы с ними
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // положили в него енкодер пароля
        daoAuthenticationProvider.setUserDetailsService(userDetailsService); // добавили внутрь userDetailsService
        return new ProviderManager(daoAuthenticationProvider); // создаем менеджера авторизации и кладем в него нашего поставщика
    }

}
