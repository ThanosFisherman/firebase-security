package com.dw.fierbase.security.config;

import com.dw.fierbase.security.filter.FirebaseAuthenticationFilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

  @Autowired
  @Qualifier("securityCacheManager")
  private CacheManager securityCacheManager;

  @Autowired
  private UserDetailsService userDetailsService;

  /**
   * Use to create instance of {@link FirebaseAuthenticationFilter}.
   * 
   * @return instance of {@link FirebaseAuthenticationFilter}
   */
  public FirebaseAuthenticationFilter firebaseAuthenticationFilterBean() throws Exception {
    logger.debug(
        "firebaseAuthenticationFilterBean():: creating instance of FirebaseAuthenticationFilter.");

    FirebaseAuthenticationFilter authenticationTokenFilter =
        new FirebaseAuthenticationFilter(securityCacheManager);

    return authenticationTokenFilter;
  }

  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {

    // @formatter:off
    httpSecurity
      .cors()
          .and()
      .csrf()
          .disable()
      .authorizeRequests()
          .antMatchers("/instruments","/zerodha-login","/zerodha-callback").permitAll()
          .anyRequest().authenticated()
          .and()
      .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
          .and()
      // basic authentication
      .httpBasic().and().userDetailsService(userDetailsService);
    // @formatter:off

    // Custom security filter
    httpSecurity.addFilterBefore(firebaseAuthenticationFilterBean(),
        UsernamePasswordAuthenticationFilter.class);
  }

}
