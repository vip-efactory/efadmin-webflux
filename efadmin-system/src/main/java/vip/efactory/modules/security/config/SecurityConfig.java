package vip.efactory.modules.security.config;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.WebFilter;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import vip.efactory.annotation.AnonymousAccess;
import vip.efactory.modules.security.security.JwtAccessDeniedHandler;
import vip.efactory.modules.security.security.JwtAuthenticationEntryPoint;
import vip.efactory.modules.security.security.TokenConfigurer;
import vip.efactory.modules.security.security.TokenProvider;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * WebFlux的安全配置
 *
 * @author dusuanyun
 */
@Configuration
@EnableWebFluxSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final WebFilter corsFilter;
    private final JwtAuthenticationEntryPoint authenticationErrorHandler;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final ApplicationContext applicationContext;

    public SecurityConfig(TokenProvider tokenProvider, WebFilter corsFilter, JwtAuthenticationEntryPoint authenticationErrorHandler, JwtAccessDeniedHandler jwtAccessDeniedHandler, ApplicationContext applicationContext) {
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.authenticationErrorHandler = authenticationErrorHandler;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.applicationContext = applicationContext;
    }

    @Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults() {
        // 去除 ROLE_ 前缀
        return new GrantedAuthorityDefaults("");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 密码加密方式
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        // 允许匿名访问的注解处理，搜寻匿名标记 url： @AnonymousAccess
        Map<RequestMappingInfo, HandlerMethod> handlerMethodMap = applicationContext.getBean(RequestMappingHandlerMapping.class).getHandlerMethods();
        Set<String> anonymousUrls = new HashSet<>();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> infoEntry : handlerMethodMap.entrySet()) {
            HandlerMethod handlerMethod = infoEntry.getValue();
            AnonymousAccess anonymousAccess = handlerMethod.getMethodAnnotation(AnonymousAccess.class);
            if (null != anonymousAccess) {
                anonymousUrls.addAll(infoEntry.getKey().getPatternsCondition().getPatterns());
            }
        }

        return http
                // 禁用 CSRF
                .cors().disable()
                .addFilterBefore(corsFilter, SecurityWebFiltersOrder.CSRF)
                // 授权异常
                .exceptionHandling()
                .authenticationEntryPoint(authenticationErrorHandler)
                .accessDeniedHandler(jwtAccessDeniedHandler)
                // 防止iframe 造成跨域
                .and()
                .headers().frameOptions().disable()
                // 不创建会话，webflux没有这个配置
                //.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeExchange()
                // 放行静态资源
                .pathMatchers(HttpMethod.GET,"/*.html",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js",
                        "/webSocket/**").permitAll()
                // 放行swagger 文档
                .pathMatchers("/swagger-ui.html").permitAll()
                .pathMatchers("/swagger-resources/**").permitAll()
                .pathMatchers("/webjars/**").permitAll()
                .pathMatchers("/*/api-docs").permitAll()
                // 文件
                .pathMatchers("/avatar/**").permitAll()
                .pathMatchers("/file/**").permitAll()
                // 阿里巴巴 druid
                .pathMatchers("/druid/**").permitAll()
                // 放行OPTIONS请求
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // 自定义匿名访问所有url放行 ： 允许匿名和带权限以及登录用户访问
                .pathMatchers(anonymousUrls.toArray(new String[0])).permitAll()
                .pathMatchers("/design", "/orders").hasAuthority("USER")
                .anyExchange().authenticated()
                .and()
                .build();
    }

    private TokenConfigurer securityConfigurerAdapter() {
        return new TokenConfigurer(tokenProvider);
    }
}
