package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model;

// В данным классе мы обозначаили права доступа для ролей
public enum Permission {

    DEVELOPERS_READ("developers:read"),
    DEVELOPERS_WRITE("developers:write");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }

}
