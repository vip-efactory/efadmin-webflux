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
   // Web MVC的配置
//   @Override
//   public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
//      //当用户在没有授权的情况下访问受保护的REST资源时，将调用此方法发送403 Forbidden响应
//      response.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
//   }

   @Override
   public Mono<Void> handle(ServerWebExchange serverWebExchange, AccessDeniedException e) {
      serverWebExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
      return serverWebExchange.getResponse().setComplete();
   }
}
