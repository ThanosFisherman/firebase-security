package com.dw.fierbase.security.filter;

import com.google.api.core.ApiFuture;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FirebaseAuthenticationFilter implements Filter {

  private static final Logger logger = LoggerFactory.getLogger(FirebaseAuthenticationFilter.class);
  private static final String TOKEN_HEADER = "X-Firebase-Auth";
  private static final String CACHE_FIREBASE_ID_TOKEN = "firebaseIdToken";

  private CacheManager cacheManager;

  public FirebaseAuthenticationFilter(CacheManager cacheManager) {
    this.cacheManager = cacheManager;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    logger.debug("init():: FirebaseAuthenticationFilter initialization.");
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String authToken = httpRequest.getHeader(TOKEN_HEADER);

    if (StringUtils.isBlank(authToken)) {
      logger.debug("Authentication token is null or blank.");
      chain.doFilter(request, response);
      return;
    }

    String obfuscateToken = StringUtils.abbreviateMiddle(authToken, "...", 53);
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    try {
      Authentication authentication = getAndValidateAuthentication(authToken);

      SecurityContextHolder.getContext().setAuthentication(authentication);
      logger.debug("doFilter():: Succeed authentication for token: {}", obfuscateToken);
    } catch (FirebaseAuthException ex) {
      httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      logger.debug("Invalid authentication for token: {}.", obfuscateToken, ex);
    } catch (Exception ex) {
      httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      logger.error("Authentication error for token: {}”.", obfuscateToken, ex);
      return;
    }

    chain.doFilter(request, response);
  }

  private Authentication getAndValidateAuthentication(String authToken) throws Exception {
    Authentication authentication = null;

    Cache cache = cacheManager.getCache(CACHE_FIREBASE_ID_TOKEN);
    if (cache.get(authToken) != null) {
      authentication = cache.get(authToken, Authentication.class);
      return authentication;
    }

    FirebaseToken firebaseToken = authenticateFirebaseToken(authToken);
    authentication =
        new UsernamePasswordAuthenticationToken(firebaseToken, authToken, new ArrayList<>());
    cache.put(authToken, authentication);
    return authentication;
  }

  private FirebaseToken authenticateFirebaseToken(String authToken) throws Exception {
    ApiFuture<FirebaseToken> app = FirebaseAuth.getInstance().verifyIdTokenAsync(authToken);

    try {
      return app.get();
    } catch (InterruptedException | ExecutionException ex) {
      throw ex;
    }
  }

  @Override
  public void destroy() {
    logger.debug("destroy():: invoke");
  }
}
