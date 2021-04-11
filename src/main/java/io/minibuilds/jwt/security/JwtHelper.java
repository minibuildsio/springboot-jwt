package io.minibuilds.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.stream.Collectors;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

@Service
public class JwtHelper {

  private static final String ROLES = "roles";

  private final byte[] jwtSecret;
  private final long jwtLifeSpan;

  public JwtHelper(@Value("${jwt.secret}") String jwtSecret, @Value("${jwt.life-span}") long jwtLifeSpan) {
    this.jwtSecret = jwtSecret.getBytes();
    this.jwtLifeSpan = jwtLifeSpan;
  }

  public String createJwt(User user) {
    return JWT.create()
        .withSubject(user.getUsername())
        .withArrayClaim(ROLES, user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray(String[]::new))
        .withExpiresAt(new Date(System.currentTimeMillis() + jwtLifeSpan))
        .sign(HMAC512(this.jwtSecret));
  }

  public User extractUser(String token) {
    DecodedJWT jwt = JWT.require(Algorithm.HMAC512(this.jwtSecret))
        .build()
        .verify(token);

    return new User(jwt.getSubject(), "", jwt.getClaim(ROLES).asList(String.class).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
  }
}
