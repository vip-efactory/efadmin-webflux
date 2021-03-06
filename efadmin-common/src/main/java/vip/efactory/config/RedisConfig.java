package vip.efactory.config;

import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.serializer.SerializerFeature;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.CacheErrorHandler;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisClientConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.*;
import org.springframework.util.Assert;
import vip.efactory.common.base.utils.MapUtil;
import vip.efactory.config.cache.XRedisConnectionFactory;
import vip.efactory.ejpa.tenant.identifier.TenantHolder;
import vip.efactory.utils.StringUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * @author Zheng Jie
 * @date 2018-11-24
 */
@Slf4j
@Configuration
@EnableCaching
@ConditionalOnClass(RedisOperations.class)
@EnableConfigurationProperties(RedisProperties.class)
public class RedisConfig extends CachingConfigurerSupport {

    @Autowired
    private Environment env;

    /**
     * ?????? redis ?????????????????????????????????2??????
     * ??????@cacheable ???????????????
     */
    @Bean
    public RedisCacheConfiguration redisCacheConfiguration() {
        RedisCacheConfiguration configuration = RedisCacheConfiguration.defaultCacheConfig();
        configuration = configuration.serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new FastJsonRedisSerializer<>(Object.class))).entryTtl(Duration.ofHours(2));
        return configuration;
    }

    @Bean
    @Primary
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<String, Object>();
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());

        // value?????????????????????fastJsonRedisSerializer
        FastJsonRedisSerializer<Object> fastJsonRedisSerializer = new FastJsonRedisSerializer<>(Object.class);
        // ????????????AutoType?????????????????????????????????????????????
        // ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // ???????????????????????????????????????????????????
        ParserConfig.getGlobalInstance().addAccept("vip.efactory");
        redisTemplate.setValueSerializer(fastJsonRedisSerializer);
        redisTemplate.setHashValueSerializer(fastJsonRedisSerializer);
        redisTemplate.setConnectionFactory(jedisConnectionFactory());
        return redisTemplate;
    }

    /**
     * ?????????????????????redis????????????????????????????????????????????????
     *
     * @return
     */
    private RedisClusterConfiguration getClusterConfiguration() {
        Map<String, Object> source = new HashMap<>(2);
        String clusterNodes = env.getProperty("spring.redis.cluster.nodes");
        source.put("spring.redis.cluster.nodes", clusterNodes);
        String clusterPassword = env.getProperty("spring.redis.cluster.password");
        source.put("spring.redis.cluster.password", clusterPassword);
        return new RedisClusterConfiguration(new MapPropertySource("RedisClusterConfiguration", source));
    }

    /**
     * ???redis?????????????????????????????????redis?????????????????????????????????????????????redis??????????????????,@Bean????????????????????????????????????????????????????????????
     *
     * @return JedisConnectionFactory
     */
    @Bean
    public JedisConnectionFactory jedisConnectionFactory() {
        XRedisConnectionFactory redisConnectionFactory = null;
        String clusterEnable = env.getProperty("spring.redis.cluster.enable");
        // ??????????????????Standalone???Sentinel and Cluster,????????????????????????
        // ????????????
        if ("true".equals(clusterEnable)) {
            redisConnectionFactory = new XRedisConnectionFactory(getClusterConfiguration());
            // Sentinel???Cluster?????????????????????????????????????????????
        } else {
            // ???????????????,????????????RedisSentinelConfiguration
            RedisStandaloneConfiguration standaloneConfiguration = new RedisStandaloneConfiguration();
            String host = env.getProperty("spring.redis.host");
            String port = env.getProperty("spring.redis.port");
            String password = env.getProperty("spring.redis.password");
            assert host != null;
            standaloneConfiguration.setHostName(host);
            assert port != null;
            standaloneConfiguration.setPort(Integer.parseInt(port));
            standaloneConfiguration.setPassword(password);
            standaloneConfiguration.setDatabase(TenantHolder.getTenantId().intValue());
            JedisClientConfiguration jedisClientConfiguration = JedisClientConfiguration.defaultConfiguration();
            redisConnectionFactory = new XRedisConnectionFactory(standaloneConfiguration, jedisClientConfiguration);
        }

        redisConnectionFactory.afterPropertiesSet();
        return redisConnectionFactory;
    }


//    @SuppressWarnings("all")
//    @Bean(name = "redisTemplate")
//    @ConditionalOnMissingBean(name = "redisTemplate")
//    public RedisTemplate<Object, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
//        RedisTemplate<Object, Object> template = new RedisTemplate<>();
//        //?????????
//        FastJsonRedisSerializer<Object> fastJsonRedisSerializer = new FastJsonRedisSerializer<>(Object.class);
//        // value?????????????????????fastJsonRedisSerializer
//        template.setValueSerializer(fastJsonRedisSerializer);
//        template.setHashValueSerializer(fastJsonRedisSerializer);
//        // ????????????AutoType?????????????????????????????????????????????
//        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
//        // ???????????????????????????????????????????????????
//        // ParserConfig.getGlobalInstance().addAccept("me.zhengjie.domain");
//        // key??????????????????StringRedisSerializer
//        template.setKeySerializer(new StringRedisSerializer());
//        template.setHashKeySerializer(new StringRedisSerializer());
//        template.setConnectionFactory(redisConnectionFactory);
//        return template;
//    }

    /**
     * ???????????????key???????????????????????????????????????
     */
    @Bean
    @Override
    public KeyGenerator keyGenerator() {
        return (target, method, params) -> {
            Map<String, Object> container = new HashMap<>(3);
            Class<?> targetClassClass = target.getClass();
            // ?????????
            container.put("className", targetClassClass.toGenericString());
            // ????????????
            container.put("methodName", method.getName());
            // ?????????
            container.put("packageName", targetClassClass.getPackage());
            // ????????????
            for (Object param : params) {
                // ?????????????????????????????????map?????????????????????????????????lambda??????????????????objectMap???????????????????????????????????????null?????????
                Map<String, Object> objectMap = (Map<String, Object>) MapUtil.objectToMap1(param);
                // ?????????????????????????????????
                container.putAll(objectMap);
            }
            // ??????JSON?????????
            String jsonString = JSONUtil.toJsonStr(container);
            // ???SHA256 Hash?????????????????????SHA256????????????Key
            return DigestUtils.sha256Hex(jsonString);
        };
    }

    @Bean
    @Override
    public CacheErrorHandler errorHandler() {
        // ??????????????????Redis??????????????????????????????????????????????????????
        log.info("????????? -> [{}]", "Redis CacheErrorHandler");
        return new CacheErrorHandler() {
            @Override
            public void handleCacheGetError(RuntimeException e, Cache cache, Object key) {
                log.error("Redis occur handleCacheGetError???key -> [{}]", key, e);
            }

            @Override
            public void handleCachePutError(RuntimeException e, Cache cache, Object key, Object value) {
                log.error("Redis occur handleCachePutError???key -> [{}]???value -> [{}]", key, value, e);
            }

            @Override
            public void handleCacheEvictError(RuntimeException e, Cache cache, Object key) {
                log.error("Redis occur handleCacheEvictError???key -> [{}]", key, e);
            }

            @Override
            public void handleCacheClearError(RuntimeException e, Cache cache) {
                log.error("Redis occur handleCacheClearError???", e);
            }
        };
    }

}

/**
 * Value ?????????
 *
 * @param <T>
 * @author /
 */
class FastJsonRedisSerializer<T> implements RedisSerializer<T> {

    private Class<T> clazz;

    FastJsonRedisSerializer(Class<T> clazz) {
        super();
        this.clazz = clazz;
    }

    @Override
    public byte[] serialize(T t) {
        if (t == null) {
            return new byte[0];
        }
        return JSON.toJSONString(t, SerializerFeature.WriteClassName).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public T deserialize(byte[] bytes) {
        if (bytes == null || bytes.length <= 0) {
            return null;
        }
        String str = new String(bytes, StandardCharsets.UTF_8);
        return JSON.parseObject(str, clazz);
    }

}

/**
 * ??????????????????
 *
 * @author /
 */
class StringRedisSerializer implements RedisSerializer<Object> {

    private final Charset charset;

    StringRedisSerializer() {
        this(StandardCharsets.UTF_8);
    }

    private StringRedisSerializer(Charset charset) {
        Assert.notNull(charset, "Charset must not be null!");
        this.charset = charset;
    }

    @Override
    public String deserialize(byte[] bytes) {
        return (bytes == null ? null : new String(bytes, charset));
    }

    @Override
    public byte[] serialize(Object object) {
        String string = JSON.toJSONString(object);
        if (isBlank(string)) {
            return null;
        }
        string = string.replace("\"", "");
        return string.getBytes(charset);
    }
}
