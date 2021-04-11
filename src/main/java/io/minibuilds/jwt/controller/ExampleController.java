package io.minibuilds.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ExampleController {

  @GetMapping("/me")
  public Map<String, String> me(Authentication authentication) {
    return Map.of("message", "Hello " + ((User) authentication.getPrincipal()).getUsername());
  }

  @PreAuthorize("hasAuthority('ADMIN')")
  @GetMapping("/adminonly")
  public Map<String, String> adminOnly() {
    return Map.of("message", "Hello you are special");
  }
}
