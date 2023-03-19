package com.example.ss_l4.config.filters;
import com.example.ss_l4.config.authentications.ApiKeyAuthentication;
import com.example.ss_l4.config.managers.CustomAuthenticationManager;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {

  private final String key;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    CustomAuthenticationManager manager = new CustomAuthenticationManager(key);

    String requestKey = request.getHeader("x-api-key");

    if (requestKey == null || "null".equals(requestKey)) {
      filterChain.doFilter(request, response);
    }

    ApiKeyAuthentication auth = new ApiKeyAuthentication(requestKey);

    try {
      Authentication a = manager.authenticate(auth);
      if (a.isAuthenticated()) {
        SecurityContextHolder.getContext().setAuthentication(a);
        filterChain.doFilter(request, response);
      } else {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
    } catch (AuthenticationException e) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
  }
}
