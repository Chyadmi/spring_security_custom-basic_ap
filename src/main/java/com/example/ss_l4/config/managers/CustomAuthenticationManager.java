package com.example.ss_l4.config.managers;

import com.example.ss_l4.config.providers.ApiKeyProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@AllArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

  private final String key;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ApiKeyProvider provider = new ApiKeyProvider(key);
    if (provider.supports(authentication.getClass())) {
      return provider.authenticate(authentication);
    }

    return authentication;
  }
}
