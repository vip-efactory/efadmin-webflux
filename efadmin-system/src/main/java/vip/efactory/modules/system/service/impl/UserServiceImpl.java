package vip.efactory.modules.system.service.impl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import vip.efactory.common.base.page.EPage;
import vip.efactory.ejpa.base.service.impl.BaseServiceImpl;
import vip.efactory.ejpa.tenant.identifier.TenantHolder;
import vip.efactory.exception.EntityExistException;
import vip.efactory.exception.EntityNotFoundException;
import vip.efactory.modules.system.domain.User;
import vip.efactory.modules.system.domain.UserAvatar;
import vip.efactory.modules.system.repository.UserAvatarRepository;
import vip.efactory.modules.system.repository.UserRepository;
import vip.efactory.modules.system.service.UserService;
import vip.efactory.modules.system.service.dto.RoleSmallDto;
import vip.efactory.modules.system.service.dto.UserDto;
import vip.efactory.modules.system.service.dto.UserQueryCriteria;
import vip.efactory.modules.system.service.mapper.UserMapper;
import vip.efactory.utils.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static cn.hutool.core.io.FileUtil.del;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Service
@CacheConfig(cacheNames = "user")
@Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
public class UserServiceImpl extends BaseServiceImpl<User, Long, UserRepository> implements UserService {

    private final UserMapper userMapper;
    private final RedisUtils redisUtils;
    private final UserAvatarRepository userAvatarRepository;

    @Value("${file.avatar}")
    private String avatar;

    public UserServiceImpl(UserMapper userMapper, RedisUtils redisUtils, UserAvatarRepository userAvatarRepository) {
        this.userMapper = userMapper;
        this.redisUtils = redisUtils;
        this.userAvatarRepository = userAvatarRepository;
    }

    @Override
    @Cacheable
    public Object queryAll(UserQueryCriteria criteria, Pageable pageable) {
        Page<User> page = br.findAll((root, criteriaQuery, criteriaBuilder) -> QueryHelp.getPredicate(root, criteria, criteriaBuilder), pageable);
        return new EPage(page.map(userMapper::toDto));
    }

    @Override
    @Cacheable
    public List<UserDto> queryAll(UserQueryCriteria criteria) {
        List<User> users = br.findAll((root, criteriaQuery, criteriaBuilder) -> QueryHelp.getPredicate(root, criteria, criteriaBuilder));
        return userMapper.toDto(users);
    }

    @Override
    @Cacheable(key = "#p0")
    public UserDto findDtoById(long id) {
        User user = br.findById(id).orElseGet(User::new);
        ValidationUtil.isNull(user.getId(), "User", "id", id);
        return userMapper.toDto(user);
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public UserDto create(User resources) {
        if (br.findByUsername(resources.getUsername()) != null) {
            throw new EntityExistException(User.class, "username", resources.getUsername());
        }
        if (br.findByEmail(resources.getEmail()) != null) {
            throw new EntityExistException(User.class, "email", resources.getEmail());
        }
        return userMapper.toDto(br.save(resources));
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void update2(User resources) {
        User user = br.findById(resources.getId()).orElseGet(User::new);
        ValidationUtil.isNull(user.getId(), "User", "id", resources.getId());
        User user1 = br.findByUsername(user.getUsername());
        User user2 = br.findByEmail(user.getEmail());

        if (user1 != null && !user.getId().equals(user1.getId())) {
            throw new EntityExistException(User.class, "username", resources.getUsername());
        }

        if (user2 != null && !user.getId().equals(user2.getId())) {
            throw new EntityExistException(User.class, "email", resources.getEmail());
        }

        // ????????????????????????????????????????????????????????????
        if (!resources.getRoles().equals(user.getRoles())) {
            String key = "role::loadPermissionByUser:" + user.getUsername();
            redisUtils.del(key);
            key = "role::findByUsers_Id:" + user.getId();
            redisUtils.del(key);
        }

        user.setUsername(resources.getUsername());
        user.setEmail(resources.getEmail());
        user.setEnabled(resources.getEnabled());
        user.setRoles(resources.getRoles());
        user.setDept(resources.getDept());
        user.setJob(resources.getJob());
        user.setPhone(resources.getPhone());
        user.setNickName(resources.getNickName());
        user.setSex(resources.getSex());
        br.save(user);
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void updateCenter(User resources) {
        User user = br.findById(resources.getId()).orElseGet(User::new);
        user.setNickName(resources.getNickName());
        user.setPhone(resources.getPhone());
        user.setSex(resources.getSex());
        br.save(user);
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void delete(Set<Long> ids) {
        for (Long id : ids) {
            br.deleteById(id);
        }
    }

    @Override
    @Cacheable(key = "'loadUserByUsername:'+#p0")
    public UserDto findByName(String userName) {
        User user;
        if (ValidationUtil.isEmail(userName)) {
            user = br.findByEmail(userName);
        } else {
            user = br.findByUsername(userName);
        }
        if (user == null) {
            throw new EntityNotFoundException(User.class, "name", userName);
        } else {
            return userMapper.toDto(user);
        }
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void updatePass(String username, String pass) {
        br.updatePass(username, pass, new Date());
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void updateAvatar(MultipartFile multipartFile) {
        User user = br.findByUsername(SecurityUtils.getUsername());
        UserAvatar userAvatar = user.getUserAvatar();
        String oldPath = "";
        if (userAvatar != null) {
            oldPath = userAvatar.getPath();
        }
        String finalAvatar = avatar + File.separator + TenantHolder.getTenantId() + File.separator;  // ???????????????????????????????????????
        File file = FileUtil.upload(multipartFile, finalAvatar);
        assert file != null;
        // ????????????????????????UserAvatar.realName??????,?????????????????????
        userAvatar = userAvatarRepository.save(new UserAvatar(userAvatar, TenantHolder.getTenantId() + File.separator + file.getName(), file.getPath(), FileUtil.getSize(multipartFile.getSize())));
        user.setUserAvatar(userAvatar);
        br.save(user);
        //?????????????????????????????????????????????
        if (isNotBlank(oldPath)) {
            del(oldPath);
        }
    }

    @Override
    @CacheEvict(allEntries = true)
    @Transactional(rollbackFor = Exception.class)
    public void updateEmail(String username, String email) {
        br.updateEmail(username, email);
    }

    @Override
    public void download(List<UserDto> queryAll, HttpServletResponse response) throws IOException {
        List<Map<String, Object>> list = new ArrayList<>();
        for (UserDto userDTO : queryAll) {
            List<String> roles = userDTO.getRoles().stream().map(RoleSmallDto::getName).collect(Collectors.toList());
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("?????????", userDTO.getUsername());
            map.put("??????", userDTO.getAvatar());
            map.put("??????", userDTO.getEmail());
            map.put("??????", userDTO.getEnabled() ? "??????" : "??????");
            map.put("????????????", userDTO.getPhone());
            map.put("??????", roles);
            map.put("??????", userDTO.getDept().getName());
            map.put("??????", userDTO.getJob().getName());
            map.put("???????????????????????????", userDTO.getLastPasswordResetTime().toString());
            map.put("????????????", userDTO.getCreateTime().toString());
            list.add(map);
        }
        FileUtil.downloadExcel(list, response);
    }
}
