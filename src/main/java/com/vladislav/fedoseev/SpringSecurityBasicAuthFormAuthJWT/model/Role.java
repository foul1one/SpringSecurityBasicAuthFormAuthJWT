package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum Role {

    ADMIN(Set.of(Permission.DEVELOPERS_READ, Permission.DEVELOPERS_WRITE)), // Здесь мы указали какие есть права доступа у ролей

    USER(Set.of(Permission.DEVELOPERS_READ));

    private final Set<Permission> permissions; // Это права доступа

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    // Здесь мы оборачиваем права доступа в SimpleGrantedAuthority, с которым умеет работать Spring Security
    public Set<SimpleGrantedAuthority> getAuthorities() {
        return getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
    }

}
