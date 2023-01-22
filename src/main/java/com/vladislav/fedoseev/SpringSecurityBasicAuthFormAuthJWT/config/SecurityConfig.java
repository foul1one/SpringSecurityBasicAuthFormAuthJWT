package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.config;

import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration // помечаем что класс является конфигурационным
@EnableWebSecurity // включаем web security
@EnableMethodSecurity // чтобы права доступа работали в контролере через аннотаицю @PreAuthorize, нужно добавить эту аннотацию
public class SecurityConfig {

    // начиная с версси секьюрити 5.7.0 конфигурация осуществляется не через наследование класса WebSecurityConfigurerAdapter
    // а через создание бина SecurityFilterChain, в котором мы настраиваем HttpSecurity
    // в HttpSecurity мы можем настроить какой вид авторизации мы будем использовать, какие енд поинты у нас открыты, какие закрыты,
    // указать пользователи с какими ролями или правами доступа могут иметь доступ к определенному енд поинту и т.д.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // отключаем csrf
                .authorizeHttpRequests() // начинаем настройку запросов, которые требуют авторизации
                .requestMatchers("/").permitAll() // к корню проекта доступ имеют все и пользователи и не пользователи системы
                .anyRequest() // каждый запрос
                .authenticated() // должен быть аутентифицирован
                .and()
                .formLogin() // аутентификация через форму
                .loginPage("/auth/login").permitAll() // здесь мы указываем путь по которому можно получить страницу аутентификации и говорим это открытый енд поинт, иначе будет ошибка
                .defaultSuccessUrl("/auth/success") // здесь мы указываем стандартную страницу успешной аутентификации, получаем эти страницы через контроллер (обычный, не рест)
                .and()
                .logout() // настраиваем логаут
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST")) // указываем путь и метод для логаута
                .invalidateHttpSession(true) // анулируем текущую сессию
                .clearAuthentication(true) // очищаем текущую аутентификацию
                .deleteCookies("JSESSIONID") // очищаем куки
                .logoutSuccessUrl("/auth/login"); // при успешном логауте перенаправляем по пути
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
//                        .roles(Role.ADMIN.name()) тут мы указывали роль
//                        Теперь мы указываем права доступа роли
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user"))
                        .authorities(Role.USER.getAuthorities())
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
