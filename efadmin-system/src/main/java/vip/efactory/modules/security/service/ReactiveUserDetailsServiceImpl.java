package vip.efactory.modules.security.service;


import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;
import vip.efactory.exception.BadRequestException;
import vip.efactory.modules.security.security.vo.JwtUser;
import vip.efactory.modules.system.service.RoleService;
import vip.efactory.modules.system.service.UserService;
import vip.efactory.modules.system.service.dto.DeptSmallDto;
import vip.efactory.modules.system.service.dto.JobSmallDto;
import vip.efactory.modules.system.service.dto.UserDto;

import java.util.Optional;


/**
 * 反应式的UserDetailsService
 * @author dusuanyun
 */
@Service("userDetailsService")
@Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
public class ReactiveUserDetailsServiceImpl implements ReactiveUserDetailsService {

    private final UserService userService;
    private final RoleService roleService;

    public ReactiveUserDetailsServiceImpl(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        UserDto user = userService.findByName(username);
        if (user == null) {
            throw new BadRequestException("账号不存在");
        } else {
            if (Boolean.FALSE.equals(user.getEnabled())) {
                throw new BadRequestException("账号未激活");
            }
            return createJwtUser(user);
        }
    }

    private Mono<UserDetails> createJwtUser(UserDto user) {
        UserDetails userDetails = new JwtUser(
                user.getId(),
                user.getUsername(),
                user.getNickName(),
                user.getSex(),
                user.getPassword(),
                user.getAvatar(),
                user.getEmail(),
                user.getPhone(),
                Optional.ofNullable(user.getDept()).map(DeptSmallDto::getName).orElse(null),
                Optional.ofNullable(user.getJob()).map(JobSmallDto::getName).orElse(null),
                roleService.mapToGrantedAuthorities(user),
                user.getEnabled(),
                user.getCreateTime(),
                user.getLastPasswordResetTime()
        );
        // 转换为Mono的方式
        return Mono.just(userDetails);
    }
}
