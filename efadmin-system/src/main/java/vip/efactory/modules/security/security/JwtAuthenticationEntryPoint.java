package vip.efactory.modules.security.security;


import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author dusuanyun
 */
@Component
public class JwtAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    // 这是WebMVC的模式
//    @Override
//    public void commence(HttpServletRequest request,
//                         HttpServletResponse response,
//                         AuthenticationException authException) throws IOException {
//        // 当用户尝试访问安全的REST资源而不提供任何凭据时，将调用此方法发送401 响应
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException==null?"Unauthorized":authException.getMessage());
//    }

    /**
     * 此处可能会有问题，后续研究如何优化，异常信息没有用上
     * @param serverWebExchange 交换机
     * @param authException  认证异常信息
     * @return Mono<Void>
     */
    @Override
    public Mono<Void> commence(ServerWebExchange serverWebExchange, AuthenticationException authException) {
        serverWebExchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return serverWebExchange.getResponse().setComplete();
    }
}
