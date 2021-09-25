package vip.efactory.modules.monitor.service.impl;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import lombok.extern.slf4j.Slf4j;
import vip.efactory.ejpa.base.service.impl.BaseServiceImpl;
import vip.efactory.modules.monitor.domain.Visits;
import vip.efactory.modules.monitor.repository.VisitsRepository;
import vip.efactory.modules.monitor.service.VisitsService;
import vip.efactory.repository.LogRepository;
import vip.efactory.utils.StringUtils;

@Slf4j
@Service
@Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
public class VisitsServiceImpl extends BaseServiceImpl<Visits, Long, VisitsRepository> implements VisitsService {

    private final LogRepository logRepository;

    public VisitsServiceImpl(LogRepository logRepository) {
        this.logRepository = logRepository;
    }

    @Override
    public void save() {
        LocalDate localDate = LocalDate.now();
        Visits visits = br.findByDate(localDate.toString());
        if (visits == null) {
            visits = new Visits();
            visits.setWeekDay(StringUtils.getWeekDay());
            visits.setPvCounts(1L);
            visits.setIpCounts(1L);
            visits.setDate(localDate.toString());
            br.save(visits);
        }
    }

    @Override
    public void count(HttpServletRequest request) {
        LocalDate localDate = LocalDate.now();
        Visits visits = br.findByDate(localDate.toString());
        if (visits == null) {
            visits = new Visits();
            visits.setWeekDay(StringUtils.getWeekDay());
            visits.setPvCounts(1L);
            visits.setIpCounts(1L);
            visits.setDate(localDate.toString());
            br.save(visits);
        } else {
            visits.setPvCounts(visits.getPvCounts() + 1);
            long ipCounts = logRepository.findIp(localDate.toString(), localDate.plusDays(1).toString());
            visits.setIpCounts(ipCounts);
            br.save(visits);
        }
    }

    @Override
    public Object get() {
        Map<String, Object> map = new HashMap<>(4);
        LocalDate localDate = LocalDate.now();
        Visits visits = br.findByDate(localDate.toString());
        List<Visits> list = br.findAllVisits(localDate.minusDays(6).toString(), localDate.plusDays(1).toString());

        long recentVisits = 0, recentIp = 0;
        for (Visits data : list) {
            recentVisits += data.getPvCounts();
            recentIp += data.getIpCounts();
        }

        if (visits == null) {
            map.put("newVisits", 0L);
            map.put("newIp", 0L);
        } else {
            map.put("newVisits", visits.getPvCounts());
            map.put("newIp", visits.getIpCounts());
        }
        map.put("recentVisits", recentVisits);
        map.put("recentIp", recentIp);
        return map;
    }

    @Override
    public Object getChartData() {
        Map<String, Object> map = new HashMap<>(3);
        LocalDate localDate = LocalDate.now();
        List<Visits> list = br.findAllVisits(localDate.minusDays(6).toString(), localDate.plusDays(1).toString());
        map.put("weekDays", list.stream().map(Visits::getWeekDay).collect(Collectors.toList()));
        map.put("visitsData", list.stream().map(Visits::getPvCounts).collect(Collectors.toList()));
        map.put("ipData", list.stream().map(Visits::getIpCounts).collect(Collectors.toList()));
        return map;
    }
}
