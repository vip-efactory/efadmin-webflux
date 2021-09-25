package vip.efactory.modules.mnt.service;

import com.jcraft.jsch.JSchException;
import org.springframework.data.domain.Pageable;
import vip.efactory.ejpa.base.service.IBaseService;
import vip.efactory.modules.mnt.domain.ServerDeploy;
import vip.efactory.modules.mnt.service.dto.ServerDeployDto;
import vip.efactory.modules.mnt.service.dto.ServerDeployQueryCriteria;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;

public interface ServerDeployService extends IBaseService<ServerDeploy, Long> {

    /**
     * 分页查询
     *
     * @param criteria 条件
     * @param pageable 分页参数
     * @return /
     */
    Object queryAll(ServerDeployQueryCriteria criteria, Pageable pageable);

    /**
     * 查询全部数据
     *
     * @param criteria 条件
     * @return /
     */
    List<ServerDeployDto> queryAll(ServerDeployQueryCriteria criteria);

    /**
     * 根据ID查询
     *
     * @param id /
     * @return /
     */
    ServerDeployDto findDtoById(Long id);

    /**
     * 创建
     *
     * @param resources /
     * @return /
     */
    ServerDeployDto create(ServerDeploy resources);

    /**
     * 编辑
     *
     * @param resources /
     */
    void update2(ServerDeploy resources);

    /**
     * 删除
     *
     * @param ids /
     */
    void delete(Set<Long> ids);

    /**
     * 根据IP查询
     *
     * @param ip /
     * @return /
     */
    ServerDeployDto findByIp(String ip);

    /**
     * 测试登录服务器
     *
     * @param resources /
     * @return /
     */
    Boolean testConnect(ServerDeploy resources) throws JSchException;

    /**
     * 导出数据
     *
     * @param queryAll /
     * @param response /
     * @throws IOException /
     */
    void download(List<ServerDeployDto> queryAll, HttpServletResponse response) throws IOException;
}
