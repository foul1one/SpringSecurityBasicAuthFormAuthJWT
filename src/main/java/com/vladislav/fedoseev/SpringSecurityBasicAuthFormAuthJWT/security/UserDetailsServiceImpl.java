package com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.security;

import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.model.User;
import com.vladislav.fedoseev.SpringSecurityBasicAuthFormAuthJWT.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// Здесь мы переопределяем UserDetailsService

@Service("userDetailServiceImpl")
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Получаем пользователя из БД и мапим его в UserDetails, чтобы Spring Security мог с ним работать
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email).orElseThrow( () -> new UsernameNotFoundException("User Not Found") );
        return SecurityUser.fromUser(user);
    }

}
