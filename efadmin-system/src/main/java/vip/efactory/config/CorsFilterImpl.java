package vip.efactory.config;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Description: WebFlux框架下的跨域配置实现类
 *
 * @Author dusuanyun
 * @Date 2021-09-25
 */
public class CorsFilterImpl implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        List<String> allAllowHeader = new ArrayList<>();
        allAllowHeader.add("*");
        List<HttpMethod> allAllowMethod = new ArrayList<>(Arrays.asList(HttpMethod.values()));
        HttpHeaders headers = exchange.getRequest().getHeaders();

        headers.setAccessControlAllowCredentials(true);
        headers.setAccessControlAllowHeaders(allAllowHeader);
        headers.setAccessControlAllowMethods(allAllowMethod);
        headers.setAccessControlAllowOrigin("*");
        return chain.filter(exchange);
    }
}
