package vip.efactory.service;


import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;
import vip.efactory.ejpa.base.service.IBaseService;
import vip.efactory.domain.Picture;
import vip.efactory.service.dto.PictureQueryCriteria;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public interface PictureService extends IBaseService<Picture, Long> {

    /**
     * 分页查询
     * @param criteria 条件
     * @param pageable 分页参数
     * @return /
     */
    Object queryAll(PictureQueryCriteria criteria, Pageable pageable);

    /**
     * 查询全部数据
     * @param criteria 条件
     * @return /
     */
    List<Picture> queryAll(PictureQueryCriteria criteria);

    /**
     * 上传文件
     * @param file /
     * @param username /
     * @return /
     */
    Picture upload(MultipartFile file, String username);

    /**
     * 根据ID查询
     * @param id /
     * @return /
     */
    Picture findById2(Long id);

    /**
     * 多选删除
     * @param ids /
     */
    void deleteAll(Long[] ids);

    /**
     * 导出
     * @param queryAll 待导出的数据
     * @param response /
     * @throws IOException /
     */
    void download(List<Picture> queryAll, HttpServletResponse response) throws IOException;

    /**
     * 同步数据
     */
    void synchronize();
}
