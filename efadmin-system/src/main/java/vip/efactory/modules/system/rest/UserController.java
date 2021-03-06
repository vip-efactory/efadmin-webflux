package vip.efactory.modules.system.rest;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import vip.efactory.aop.log.Log;
import vip.efactory.common.base.page.EPage;
import vip.efactory.config.DataScope;
import vip.efactory.domain.VerificationCode;
import vip.efactory.ejpa.base.controller.BaseController;
import vip.efactory.common.base.utils.R;
import vip.efactory.common.base.valid.Update;
import vip.efactory.exception.BadRequestException;
import vip.efactory.modules.system.domain.User;
import vip.efactory.modules.system.domain.vo.UserPassVo;
import vip.efactory.modules.system.service.DeptService;
import vip.efactory.modules.system.service.RoleService;
import vip.efactory.modules.system.service.UserService;
import vip.efactory.modules.system.service.dto.RoleSmallDto;
import vip.efactory.modules.system.service.dto.UserDto;
import vip.efactory.modules.system.service.dto.UserQueryCriteria;
import vip.efactory.service.VerificationCodeService;
import vip.efactory.utils.EfAdminConstant;
import vip.efactory.utils.SecurityUtils;

@Api(tags = "?????????????????????")
@RestController
@RequestMapping("/api/users")
@SuppressWarnings("rawtypes")   // ???????????????????????????
public class UserController extends BaseController<User, UserService, Long> {

    @Value("${rsa.private_key}")
    private String privateKey;

    private final PasswordEncoder passwordEncoder;
    private final DataScope dataScope;
    private final DeptService deptService;
    private final RoleService roleService;
    private final VerificationCodeService verificationCodeService;

    public UserController(PasswordEncoder passwordEncoder, DataScope dataScope, DeptService deptService, RoleService roleService, VerificationCodeService verificationCodeService) {
        this.passwordEncoder = passwordEncoder;
        this.dataScope = dataScope;
        this.deptService = deptService;
        this.roleService = roleService;
        this.verificationCodeService = verificationCodeService;
    }

    @Log("??????????????????")
    @ApiOperation("??????????????????")
    @GetMapping(value = "/download")
    @PreAuthorize("@p.check('user:list')")
    public void download(HttpServletResponse response, UserQueryCriteria criteria) throws IOException {
        entityService.download(entityService.queryAll(criteria), response);
    }

    @Log("????????????")
    @ApiOperation("????????????")
    @GetMapping("/page")
    @PreAuthorize("@p.check('user:list')")
    public R getUsers(UserQueryCriteria criteria, Pageable pageable) {
        Set<Long> deptSet = new HashSet<>();
        Set<Long> result = new HashSet<>();
        if (!ObjectUtils.isEmpty(criteria.getDeptId())) {
            deptSet.add(criteria.getDeptId());
            deptSet.addAll(dataScope.getDeptChildren(deptService.findByPid(criteria.getDeptId())));
        }
        // ????????????
        Set<Long> deptIds = dataScope.getDeptIds();
        // ????????????????????????????????????????????????????????????
        if (!CollectionUtils.isEmpty(deptIds) && !CollectionUtils.isEmpty(deptSet)) {
            // ?????????
            result.addAll(deptSet);
            result.retainAll(deptIds);
            // ???????????????????????????????????????
            criteria.setDeptIds(result);
            if (result.size() == 0) {
                EPage epage = EPage.page();
                epage.setTotalCount(0);
                return R.ok(epage);
            } else {
                return R.ok(entityService.queryAll(criteria, pageable));
            }
            // ???????????????
        } else {
            result.addAll(deptSet);
            result.addAll(deptIds);
            criteria.setDeptIds(result);
            return R.ok(entityService.queryAll(criteria, pageable));
        }
    }

    /**
     * Description: ????????????
     *
     * @param entity            ????????????????????????
     * @param page             ??????????????????
     * @return R
     */
    @Log("??????????????????User")
    @ApiOperation(value = "?????????????????????,??????????????????", notes = "????????????25?????????,id????????????")
    @PostMapping("/page")
    @PreAuthorize("@p.check('user:list')")
    public R advancedQuery(@RequestBody User entity, @PageableDefault(value = 25, sort = {"id"}, direction = Sort.Direction.DESC) Pageable page) {
        return super.advancedQueryByPage(page, entity);
    }

    @Log("????????????")
    @ApiOperation("????????????")
    @PostMapping
    @PreAuthorize("@p.check('user:add')")
    public R create(@Validated @RequestBody User resources) {
        checkLevel(resources);
        // ???????????? 123456
        resources.setPassword(passwordEncoder.encode("123456"));
        return R.ok(entityService.create(resources));
    }

    @Log("????????????")
    @ApiOperation("????????????")
    @PutMapping
    @PreAuthorize("@p.check('user:edit')")
    public R update(@Validated(Update.class) @RequestBody User resources) {
        checkLevel(resources);
        entityService.update2(resources);
        return R.ok();
    }

    @Log("???????????????????????????")
    @ApiOperation("???????????????????????????")
    @PutMapping(value = "center")
    public R center(@Validated(Update.class) @RequestBody User resources) {
        UserDto userDto = entityService.findByName(SecurityUtils.getUsername());
        if (!resources.getId().equals(userDto.getId())) {
            throw new BadRequestException("????????????????????????");
        }
        entityService.updateCenter(resources);
        return R.ok();
    }

    @Log("????????????")
    @ApiOperation("????????????")
    @DeleteMapping
    @PreAuthorize("@p.check('user:del')")
    public R delete(@RequestBody Set<Long> ids) {
        UserDto user = entityService.findByName(SecurityUtils.getUsername());
        for (Long id : ids) {
            Integer currentLevel = Collections.min(roleService.findByUsersId(user.getId()).stream().map(RoleSmallDto::getLevel).collect(Collectors.toList()));
            Integer optLevel = Collections.min(roleService.findByUsersId(id).stream().map(RoleSmallDto::getLevel).collect(Collectors.toList()));
            if (currentLevel > optLevel) {
                throw new BadRequestException("????????????????????????????????????" + entityService.findByName(SecurityUtils.getUsername()).getUsername());
            }
        }
        entityService.delete(ids);
        return R.ok();
    }

    @ApiOperation("????????????")
    @PostMapping(value = "/updatePass")
    public R updatePass(@RequestBody UserPassVo passVo) {
        // ????????????
        RSA rsa = new RSA(privateKey, null);
        String oldPass = new String(rsa.decrypt(passVo.getOldPass(), KeyType.PrivateKey));
        String newPass = new String(rsa.decrypt(passVo.getNewPass(), KeyType.PrivateKey));
        UserDto user = entityService.findByName(SecurityUtils.getUsername());
        if (!passwordEncoder.matches(oldPass, user.getPassword())) {
            throw new BadRequestException("??????????????????????????????");
        }
        if (passwordEncoder.matches(newPass, user.getPassword())) {
            throw new BadRequestException("?????????????????????????????????");
        }
        entityService.updatePass(user.getUsername(), passwordEncoder.encode(newPass));
        return R.ok();
    }

    @ApiOperation("????????????")
    @PostMapping(value = "/updateAvatar")
    public R updateAvatar(@RequestParam MultipartFile file) {
        entityService.updateAvatar(file);
        return R.ok();
    }

    @Log("????????????")
    @ApiOperation("????????????")
    @PostMapping(value = "/updateEmail/{code}")
    public R updateEmail(@PathVariable String code, @RequestBody User user) {
        // ????????????
        RSA rsa = new RSA(privateKey, null);
        String password = new String(rsa.decrypt(user.getPassword(), KeyType.PrivateKey));
        UserDto userDto = entityService.findByName(SecurityUtils.getUsername());
        if (!passwordEncoder.matches(password, userDto.getPassword())) {
            throw new BadRequestException("????????????");
        }
        VerificationCode verificationCode = new VerificationCode(code, EfAdminConstant.RESET_MAIL, "email", user.getEmail());
        verificationCodeService.validated(verificationCode);
        entityService.updateEmail(userDto.getUsername(), user.getEmail());
        return R.ok();
    }

    /**
     * ???????????????????????????????????????????????????????????????????????????????????????????????????
     *
     * @param resources /
     */
    private void checkLevel(User resources) {
        UserDto user = entityService.findByName(SecurityUtils.getUsername());
        Integer currentLevel = Collections.min(roleService.findByUsersId(user.getId()).stream().map(RoleSmallDto::getLevel).collect(Collectors.toList()));
        Integer optLevel = roleService.findByRoles(resources.getRoles());
        if (currentLevel > optLevel) {
            throw new BadRequestException("??????????????????");
        }
    }
}
