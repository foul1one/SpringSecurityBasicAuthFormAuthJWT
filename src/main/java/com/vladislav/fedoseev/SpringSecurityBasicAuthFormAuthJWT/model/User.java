package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email")
    private String email;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "password_user")
    private String password;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "role_user")
    private Role role;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "status_user")
    private Status status;

}
