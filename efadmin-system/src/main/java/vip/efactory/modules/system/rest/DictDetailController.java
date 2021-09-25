package vip.efactory.modules.system.rest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import vip.efactory.aop.log.Log;
import vip.efactory.common.base.utils.R;
import vip.efactory.common.base.valid.Update;
import vip.efactory.ejpa.base.controller.BaseController;

import vip.efactory.exception.BadRequestException;
import vip.efactory.modules.system.domain.DictDetail;
import vip.efactory.modules.system.service.DictDetailService;
import vip.efactory.modules.system.service.dto.DictDetailQueryCriteria;

@RestController
@Api(tags = "系统：字典详情管理")
@RequestMapping("/api/dictDetail")
@SuppressWarnings("rawtypes")   // 压制原生类型的警告
public class DictDetailController extends BaseController<DictDetail, DictDetailService, Long> {

    private static final String ENTITY_NAME = "dictDetail";

    @Log("查询字典详情")
    @ApiOperation("查询字典详情")
    @GetMapping("/page")
    public R getDictDetails(DictDetailQueryCriteria criteria,
                            @PageableDefault(sort = {"sort"}, direction = Sort.Direction.ASC) Pageable pageable) {
        return R.ok(entityService.queryAll(criteria, pageable));
    }

    /**
     * Description: 高级查询
     *
     * @param entity            含有高级查询条件
     * @param page             分页参数对象
     * @return R
     */
    @Log("分页高级查询DictDetail")
    @ApiOperation(value = "多条件组合查询,返回分页数据", notes = "默认每页25条记录,id字段降序")
    @PostMapping("/page")
    public R advancedQuery(@RequestBody DictDetail entity, @PageableDefault(value = 25, sort = {"id"}, direction = Sort.Direction.DESC) Pageable page) {
        return super.advancedQueryByPage(page, entity);
    }

    @Log("查询多个字典详情")
    @ApiOperation("查询多个字典详情")
    @GetMapping(value = "/map")
    public R getDictDetailMaps(DictDetailQueryCriteria criteria,
                               @PageableDefault(sort = {"sort"}, direction = Sort.Direction.ASC) Pageable pageable) {
        String[] names = criteria.getDictName().split(",");
        Map<String, Object> map = new HashMap<>(names.length);
        for (String name : names) {
            criteria.setDictName(name);
            map.put(name, entityService.queryAll(criteria, pageable).get("content"));
        }
        return R.ok(map);
    }

    @Log("新增字典详情")
    @ApiOperation("新增字典详情")
    @PostMapping
    @PreAuthorize("@p.check('dict:add')")
    public R create(@Validated @RequestBody DictDetail resources) {
        if (resources.getId() != null) {
            throw new BadRequestException("A new " + ENTITY_NAME + " cannot already have an ID");
        }
        return R.ok(entityService.create(resources));
    }

    @Log("修改字典详情")
    @ApiOperation("修改字典详情")
    @PutMapping
    @PreAuthorize("@p.check('dict:edit')")
    public R update(@Validated(Update.class) @RequestBody DictDetail resources) {
        entityService.update2(resources);
        return R.ok();
    }

    @Log("删除字典详情")
    @ApiOperation("删除字典详情")
    @DeleteMapping(value = "/{id}")
    @PreAuthorize("@p.check('dict:del')")
    public R delete(@PathVariable Long id) {
        entityService.delete(id);
        return R.ok();
    }
}
