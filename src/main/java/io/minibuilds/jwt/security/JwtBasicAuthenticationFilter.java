package io.minibuilds.jwt.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtBasicAuthenticationFilter extends BasicAuthenticationFilter {

  public static final String AUTHORIZATION = "Authorization";
  public static final String BEARER = "Bearer ";

  private final JwtHelper jwtHelper;

  public JwtBasicAuthenticationFilter(AuthenticationManager authManager, JwtHelper jwtHelper) {
    super(authManager);
    this.jwtHelper = jwtHelper;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req,
                                  HttpServletResponse res,
                                  FilterChain chain) throws IOException, ServletException {
    String header = req.getHeader(AUTHORIZATION);

    if (header == null || !header.startsWith(BEARER)) {
      chain.doFilter(req, res);
      return;
    }

    SecurityContextHolder.getContext().setAuthentication(getAuthentication(header));
    chain.doFilter(req, res);
  }

  private UsernamePasswordAuthenticationToken getAuthentication(String header) {
    if (header != null) {
      User user = this.jwtHelper.extractUser(header.replace(BEARER, ""));

      if (user != null) {
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
      }
    }
    return null;
  }
}
