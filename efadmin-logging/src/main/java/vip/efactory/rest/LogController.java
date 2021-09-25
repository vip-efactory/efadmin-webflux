package vip.efactory.rest;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import vip.efactory.aop.log.Log;
import vip.efactory.common.base.entity.BaseSearchField;
import vip.efactory.common.base.enums.ConditionRelationEnum;
import vip.efactory.common.base.enums.SearchTypeEnum;
import vip.efactory.common.base.utils.R;
import vip.efactory.domain.SysLog;
import vip.efactory.ejpa.base.controller.BaseController;

import vip.efactory.service.LogService;
import vip.efactory.service.dto.LogQueryCriteria;
import vip.efactory.utils.SecurityUtils;

/**
 * Description:
 *
 * @author dbdu
 * @date 19-7-10 上午10:44
 */
@RestController
@RequestMapping("/api/logs")
@Api(tags = "监控：日志管理")
@SuppressWarnings("rawtypes")   // 压制原生类型的警告
public class LogController extends BaseController<SysLog, LogService, Long> {

    @Log("导出数据")
    @ApiOperation("导出数据")
    @GetMapping(value = "/download")
    @PreAuthorize("@p.check()")
    public void download(HttpServletResponse response, LogQueryCriteria criteria) throws IOException {
        criteria.setLogType("INFO");
        entityService.download(entityService.queryAll(criteria), response);
    }

    @Log("导出错误数据")
    @ApiOperation("导出错误数据")
    @GetMapping(value = "/error/download")
    @PreAuthorize("@p.check()")
    public void errorDownload(HttpServletResponse response, LogQueryCriteria criteria) throws IOException {
        criteria.setLogType("ERROR");
        entityService.download(entityService.queryAll(criteria), response);
    }

    @GetMapping
    @ApiOperation("日志查询")
    @PreAuthorize("@p.check()")
    public R getLogs(LogQueryCriteria criteria, Pageable pageable) {
        criteria.setLogType("INFO");
        return R.ok(entityService.queryAll(criteria, pageable));
    }

    /**
     * Description: 高级查询,info级别
     *
     * @param entity 含有高级查询条件
     * @param page             分页参数对象
     * @return R
     */
    @ApiOperation(value = "多条件组合查询,返回分页数据", notes = "默认每页25条记录,id字段降序")
    @PostMapping
    @PreAuthorize("@p.check()")
    public R advancedQuery(@RequestBody SysLog entity, @PageableDefault(value = 25, sort = {"id"}, direction = Sort.Direction.DESC) Pageable page) {
        BaseSearchField condition = new BaseSearchField();
        condition.setName("logType");
        condition.setSearchType(SearchTypeEnum.EQ.getValue());
        condition.setVal("INFO");
        condition.setLogicalType(ConditionRelationEnum.AND.getValue());
        condition.setOrder(999);
        condition.setLogicalTypeGroup(ConditionRelationEnum.AND.getValue());
        condition.setBracketsGroup("INFO_GROUP");
        entity.getConditions().add(condition);
        return super.advancedQueryByPage(page, entity);
    }

    @GetMapping(value = "/user")
    @ApiOperation("用户日志查询")
    public R getUserLogs(LogQueryCriteria criteria, Pageable pageable) {
        criteria.setLogType("INFO");
        criteria.setBlurry(SecurityUtils.getUsername());
        return R.ok(entityService.queryAllByUser(criteria, pageable));
    }

    @GetMapping(value = "/error")
    @ApiOperation("错误日志查询")
    @PreAuthorize("@p.check()")
    public R getErrorLogs(LogQueryCriteria criteria, Pageable pageable) {
        criteria.setLogType("ERROR");
        return R.ok(entityService.queryAll(criteria, pageable));
    }

    /**
     * Description: 高级查询,error级别
     *
     * @param baseSearchEntity 含有高级查询条件
     * @param page             分页参数对象
     * @return R
     */
    @ApiOperation(value = "多条件组合查询,返回分页数据", notes = "默认每页25条记录,id字段降序")
    @PostMapping("/error")
    @PreAuthorize("@p.check()")
    public R advancedQuery4Error(@RequestBody SysLog entity, @PageableDefault(value = 25, sort = {"id"}, direction = Sort.Direction.DESC) Pageable page) {
        BaseSearchField condition = new BaseSearchField();
        condition.setName("logType");
        condition.setSearchType(SearchTypeEnum.EQ.getValue());
        condition.setVal("ERROR");
        condition.setLogicalType(ConditionRelationEnum.AND.getValue());
        condition.setOrder(999);
        condition.setLogicalTypeGroup(ConditionRelationEnum.AND.getValue());
        condition.setBracketsGroup("ERROR_GROUP");
        entity.getConditions().add(condition);
        return super.advancedQueryByPage(page, entity);
    }

    @GetMapping(value = "/error/{id}")
    @ApiOperation("日志异常详情查询")
    @PreAuthorize("@p.check()")
    public R getErrorLogs(@PathVariable Long id) {
        return R.ok(entityService.findByErrDetail(id));
    }

    @DeleteMapping(value = "/del/error")
    @Log("删除所有ERROR日志")
    @ApiOperation("删除所有ERROR日志")
    @PreAuthorize("@p.check()")
    public R delAllByError() {
        entityService.delAllByError();
        return R.ok();
    }

    @DeleteMapping(value = "/del/info")
    @Log("删除所有INFO日志")
    @ApiOperation("删除所有INFO日志")
    @PreAuthorize("@p.check()")
    public R delAllByInfo() {
        entityService.delAllByInfo();
        return R.ok();
    }
}
