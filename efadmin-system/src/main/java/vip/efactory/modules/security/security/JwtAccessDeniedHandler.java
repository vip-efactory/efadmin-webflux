package vip.efactory.modules.security.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 访问拒绝处理器
 * @author dusuanyun
 */
@Component
public class JwtAccessDeniedHandler implements ServerAccessDeniedHandler {

   @Override
   public Mono<Void> handle(ServerWebExchange serverWebExchange, AccessDeniedException e) {
      serverWebExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
      return serverWebExchange.getResponse().setComplete();
   }
}
