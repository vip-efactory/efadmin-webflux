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
