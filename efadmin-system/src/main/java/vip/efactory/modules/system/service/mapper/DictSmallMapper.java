package vip.efactory.modules.system.service.mapper;


import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;
import vip.efactory.base.BaseMapper;
import vip.efactory.modules.system.domain.Dict;
import vip.efactory.modules.system.service.dto.DictSmallDto;

/**
* @author Zheng Jie
* @date 2019-04-10
*/
@Mapper(componentModel = "spring",unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface DictSmallMapper extends BaseMapper<DictSmallDto, Dict> {

}