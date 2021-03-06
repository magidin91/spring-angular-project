package ru.dfsystems.spring.tutorial.service;

import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.BaseDao;
import ru.dfsystems.spring.tutorial.dao.BaseListDao;
import ru.dfsystems.spring.tutorial.dto.BaseDto;
import ru.dfsystems.spring.tutorial.dto.BaseListDto;
import ru.dfsystems.spring.tutorial.dto.Page;
import ru.dfsystems.spring.tutorial.dto.PageParams;
import ru.dfsystems.spring.tutorial.enums.ActionTypeEnum;
import ru.dfsystems.spring.tutorial.generate.BaseJooq;
import ru.dfsystems.spring.tutorial.mapping.BaseMapping;

import java.time.LocalDateTime;

public abstract class BaseService<List extends BaseListDto, Dto extends BaseDto, Params, Entity extends BaseJooq> {
    private BaseMapping mappingService;
    private BaseListDao<Entity, Params> listDao;
    private BaseDao<Entity> baseDao;
    Class<List> listClass;
    Class<Entity> entityClass;
    Class<Dto> dtoClass;

    public BaseService(BaseMapping mappingService, BaseListDao<Entity, Params> listDao, BaseDao<Entity> baseDao, Class<List> listClass, Class<Dto> dtoClass, Class<Entity> entityClass) {
        this.mappingService = mappingService;
        this.listDao = listDao;
        this.baseDao = baseDao;
        this.listClass = listClass;
        this.entityClass = entityClass;
        this.dtoClass = dtoClass;
    }

    @Transactional
    public Page<List> list(PageParams<Params> pageParams) {
        Page<Entity> page = listDao.list(pageParams);
        java.util.List<List> list = mappingService.mapList(page.getList(), listClass);
        return new Page<>(list, page.getTotalCount());
    }

    @Transactional
    public Dto get(Integer idd) {
        return mappingService.map(baseDao.getActiveByIdd(idd), dtoClass);
    }

    @Transactional
    public Dto create(Dto dto, Integer userId) {
        return mappingService.map(baseDao.create(mappingService.map(dto, entityClass), userId), dtoClass);
    }

    @Transactional
    public Dto update(Integer idd, Dto dto, Integer userId) {
        Entity entity = baseDao.getActiveByIdd(idd);
        if (entity == null) {
            throw new RuntimeException("");
        }
        entity.setDeleteDate(LocalDateTime.now());
        baseDao.update(entity);

        Entity newEntity = mappingService.map(dto, entityClass);
        newEntity.setIdd(entity.getIdd());
        baseDao.create(newEntity, userId);
        return mappingService.map(newEntity, dtoClass);
    }

    @Transactional
    public void delete(Integer idd, Integer userId) {
        Entity entity = baseDao.getActiveByIdd(idd);
        entity.setDeleteDate(LocalDateTime.now());
        baseDao.update(entity);
    }

    public void process(ActionTypeEnum actionType, String objectData, Integer userId) throws Exception {
        switch (actionType) {
            case CREATE:
                doCreate(objectData, userId);
                break;
            case UPDATE:
                doUpdate(objectData, userId);
                break;
            case DELETE:
                doDelete(objectData, userId);
                break;
            default:
                throw new RuntimeException("Тип действия не найден");
        }
    }

    protected abstract void doDelete(String objectData, Integer userId) throws Exception;

    protected abstract void doUpdate(String objectData, Integer userId) throws Exception;

    protected abstract void doCreate(String objectData, Integer userId) throws Exception;
}

