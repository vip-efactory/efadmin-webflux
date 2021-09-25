package vip.efactory.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import vip.efactory.utils.SecurityUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service(value = "p")
public class EfPermissionConfig {

    public Boolean check(String ...permissions){
        // 获取当前用户的所有权限
        List<String> elPermissions = SecurityUtils.getUserDetails().getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        // 判断当前用户的所有权限是否包含接口上定义的权限
        return elPermissions.contains("admin") || Arrays.stream(permissions).anyMatch(elPermissions::contains);
    }
}
