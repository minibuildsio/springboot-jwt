package io.minibuilds.jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;


public class JwtUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final JwtHelper jwtHelper;
  private static final ObjectMapper mapper = new ObjectMapper();

  public JwtUsernamePasswordAuthenticationFilter(AuthenticationManager authManager, JwtHelper jwtHelper) {
    this.authenticationManager = authManager;
    this.jwtHelper = jwtHelper;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
    try {
      Map<String, String> creds = mapper.readValue(req.getInputStream(), Map.class);

      return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(creds.get("username"), creds.get("password")));
    } catch (IOException e) {
      throw new RuntimeException("Expected username and password");
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest req,
                                          HttpServletResponse res,
                                          FilterChain chain,
                                          Authentication auth) throws IOException {
    User user = (User) auth.getPrincipal();

    Map<String, String> response = Map.of("token", jwtHelper.createJwt(user));
    String tokenJson = mapper.writeValueAsString(response);

    res.setContentType("application/json");

    var writer = res.getWriter();
    writer.println(tokenJson);
    writer.close();
  }
}
