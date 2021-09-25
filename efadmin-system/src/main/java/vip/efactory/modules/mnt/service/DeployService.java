package vip.efactory.modules.mnt.service;

import com.jcraft.jsch.JSchException;
import org.springframework.data.domain.Pageable;
import vip.efactory.ejpa.base.service.IBaseService;
import vip.efactory.modules.mnt.domain.Deploy;
import vip.efactory.modules.mnt.domain.DeployHistory;
import vip.efactory.modules.mnt.service.dto.DeployDto;
import vip.efactory.modules.mnt.service.dto.DeployQueryCriteria;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * @author zhanghouying
 * @date 2019-08-24
 */
public interface DeployService extends IBaseService<Deploy, Long> {

    /**
     * 分页查询
     *
     * @param criteria 条件
     * @param pageable 分页参数
     * @return /
     */
    Object queryAll(DeployQueryCriteria criteria, Pageable pageable);

    /**
     * 查询全部数据
     *
     * @param criteria 条件
     * @return /
     */
    List<DeployDto> queryAll(DeployQueryCriteria criteria);

    /**
     * 根据ID查询
     *
     * @param id /
     * @return /
     */
    DeployDto findDtoById(Long id);

    /**
     * 创建
     *
     * @param resources /
     * @return /
     */
    DeployDto create(Deploy resources);


    /**
     * 编辑
     *
     * @param resources /
     */
    void update2(Deploy resources);

    /**
     * 删除
     *
     * @param ids /
     */
    void delete(Set<Long> ids);

    /**
     * 部署文件到服务器
     *
     * @param fileSavePath 文件路径
     * @param appId        应用ID
     */
    void deploy(String fileSavePath, Long appId) throws JSchException;

    /**
     * 查询部署状态
     *
     * @param resources /
     * @return /
     */
    String serverStatus(Deploy resources) throws JSchException;

    /**
     * 启动服务
     *
     * @param resources /
     * @return /
     */
    String startServer(Deploy resources) throws JSchException;

    /**
     * 停止服务
     *
     * @param resources /
     * @return /
     */
    String stopServer(Deploy resources) throws JSchException;

    /**
     * 停止服务
     *
     * @param resources /
     * @return /
     */
    String serverReduction(DeployHistory resources) throws JSchException;

    /**
     * 导出数据
     *
     * @param queryAll /
     * @param response /
     * @throws IOException /
     */
    void download(List<DeployDto> queryAll, HttpServletResponse response) throws IOException;
}
