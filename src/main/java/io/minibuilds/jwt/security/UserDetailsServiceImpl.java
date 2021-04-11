package io.minibuilds.jwt.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private final BCryptPasswordEncoder bCryptPasswordEncoder;
  private final Map<String, String> users;
  private final Map<String, List<GrantedAuthority>> authorities;

  public UserDetailsServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;

    users = new HashMap<>();
    users.put("hp", bCryptPasswordEncoder.encode("password"));
    users.put("admin", bCryptPasswordEncoder.encode("admin_password"));

    authorities = new HashMap<>();
    authorities.put("admin", List.of(new SimpleGrantedAuthority("ADMIN")));
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    if (!users.containsKey(username)) {
      throw new UsernameNotFoundException(String.format("Could not find player with username = %s", username));
    }

    return new User(username, users.get(username), authorities.getOrDefault(username, List.of()));
  }
}
