package com.example.identity.service;

import com.example.identity.dto.request.LoginRequest;
import com.example.identity.dto.response.AuthResponse;
import com.example.identity.entity.User;
import com.example.identity.repository.UserRepository;
import com.example.identity.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthResponse login(LoginRequest request) {
        // 1. Tìm user trong DB. Nếu không thấy -> ném BadCredentialsException (thông báo chung chung)
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        // 2. Đối soát mật khẩu raw với mật khẩu đã hash bằng BCrypt
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        // 3. Nếu khớp -> sinh Access Token thông qua JwtUtil
        String token = jwtUtil.generateToken(user.getUsername());

        return AuthResponse.builder()
                .accessToken(token)
                .build();
    }
}