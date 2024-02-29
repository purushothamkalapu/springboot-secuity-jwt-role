package com.purushotham.springsecurityjwtrole.controller;

import com.purushotham.springsecurityjwtrole.entity.User;
import com.purushotham.springsecurityjwtrole.response.AuthenticationResponse;
import com.purushotham.springsecurityjwtrole.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse>authenticate(@RequestBody User request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
    @GetMapping("/admin_only")
    public ResponseEntity<String> adminMinOnly(){
        return ResponseEntity.ok("admin only");
    }
}
