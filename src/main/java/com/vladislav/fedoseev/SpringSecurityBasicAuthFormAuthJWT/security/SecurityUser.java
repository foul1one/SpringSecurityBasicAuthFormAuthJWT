package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.security;

import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model.Status;
import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// Здесь мы переопределяем UserDetails. Это пользователь с которым работает Spring Security
@Data
public class SecurityUser implements UserDetails {

    // Создаем поля с которыми будем работать
    private final String username;
    private final String password;
    private final List<SimpleGrantedAuthority> authorities;
    private final boolean isActive;

    public SecurityUser(String username, String password, List<SimpleGrantedAuthority> authorities, boolean isActive) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.isActive = isActive;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() { // это более точные настройки но мы упрощаем
        return isActive;
    }

    @Override
    public boolean isAccountNonLocked() { // это более точные настройки но мы упрощаем
        return isActive;
    }

    @Override
    public boolean isCredentialsNonExpired() { // это более точные настройки но мы упрощаем
        return isActive;
    }

    @Override
    public boolean isEnabled() {
        return isActive;
    }

    // Здесь мы мапим нашего Entity юзера в UserDetails
    public static UserDetails fromUser(User user) {
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), user.getPassword(),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getStatus().equals(Status.ACTIVE),
                user.getRole().getAuthorities()
        );
    }

}
