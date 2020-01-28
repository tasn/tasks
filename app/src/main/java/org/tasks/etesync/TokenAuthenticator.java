package org.tasks.etesync;

import java.io.IOException;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class TokenAuthenticator implements Interceptor {

  private static final String HEADER_AUTHORIZATION = "Authorization";

  private final String token;

  public TokenAuthenticator(String token) {
    this.token = token;
  }

  @Override
  public Response intercept(Chain chain) throws IOException {
    Request request = chain.request();
    if (token != null && request.header(HEADER_AUTHORIZATION) == null) {
      request = request.newBuilder().header(HEADER_AUTHORIZATION, "Token " + token).build();
    }
    return chain.proceed(request);
  }
}
