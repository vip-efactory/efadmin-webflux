package vip.efactory.repository;

import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import vip.efactory.ejpa.base.repository.BaseRepository;
import vip.efactory.domain.QiniuContent;

public interface QiniuContentRepository extends BaseRepository<QiniuContent, Long>, JpaSpecificationExecutor<QiniuContent> {

    /**
     * 根据key查询
     * @param key 文件名
     * @return QiniuContent
     */
    QiniuContent findByKey(String key);
}
