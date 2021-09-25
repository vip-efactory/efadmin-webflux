package vip.efactory.modules.monitor.service;

import org.springframework.scheduling.annotation.Async;
import vip.efactory.ejpa.base.service.IBaseService;
import vip.efactory.modules.monitor.domain.Visits;

import javax.servlet.http.HttpServletRequest;

public interface VisitsService extends IBaseService<Visits, Long> {

    /**
     * 提供给定时任务，每天0点执行
     */
    void save();

    /**
     * 新增记录
     * @param request /
     */
    @Async
    void count(HttpServletRequest request);

    /**
     * 获取数据
     * @return /
     */
    Object get();

    /**
     * getChartData
     * @return /
     */
    Object getChartData();
}
