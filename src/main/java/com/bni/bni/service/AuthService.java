package com.bni.bni.service;

import com.bni.bni.entity.User;
import com.bni.bni.repository.UserRepository;
import com.bni.bni.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository repo;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtil jwtUtil;

    // register with email and default is_active = true
    public String register(String username, String password, String email) {
        if (repo.existsByUsername(username)) {
            return "User already exists";
        }

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(encoder.encode(password));
        user.setEmailAddress(email);
        user.setIsActive(true);
        user.setCreatedAt(OffsetDateTime.now());
        user.setUpdatedAt(OffsetDateTime.now());

        repo.save(user);

        return "Registered successfully";
    }

    public String login(String username, String password) {
        Optional<User> user = repo.findByUsername(username);
        if (user.isPresent() && encoder.matches(password, user.get().getPasswordHash())) {
            return jwtUtil.generateToken(username); // hanya username
        }
        return null;
    }

    // digunakan untuk /me endpoint
    public Map<String, Object> getUserDetails(String username) {
        Optional<User> optionalUser = repo.findByUsername(username);
        Map<String, Object> userDetails = new HashMap<>();

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            userDetails.put("email", user.getEmailAddress());
            userDetails.put("is_active", user.getIsActive());
            userDetails.put("created_at", user.getCreatedAt());
            userDetails.put("updated_at", user.getUpdatedAt());
        }

        return userDetails;
    }
}
