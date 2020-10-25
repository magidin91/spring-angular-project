package ru.dfsystems.spring.tutorial.security;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import ru.dfsystems.spring.tutorial.security.dto.UserDto;
import ru.dfsystems.spring.tutorial.generated.tables.daos.AppUserDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.AppUser;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

import java.time.LocalDateTime;

import static ru.dfsystems.spring.tutorial.generated.tables.AppUser.APP_USER;

@Service
@AllArgsConstructor
public class UserService {
    private AppUserDao appUserDao;
    private MappingService mappingService;
    private UserContext userContext;

    public AppUser getUserByLogin(String login){
        /* Ищем по полю LOGIN*/
        return appUserDao.fetchOptional(APP_USER.LOGIN, login)
                .orElse(null);
    }
    /* получает пользователя и сверяет пароль с фронта и в системе */
    public boolean checkPassword(String login, String password) {
        AppUser user = getUserByLogin(login);
        if (user == null) {
            return false;
        }
       /* ! Добавить соль к паролю. Соль хранить в application.yml, чтобы на разных сайтах были разные хеши для
        одних паролей */
        /* преобразуем пароль через встроенный класс DigestUtils в md5Hex строку */
        String md5Hex = DigestUtils.md5DigestAsHex(password.getBytes())
                .toUpperCase();

        return md5Hex.equals(user.getPasswordHash());
    }
    /* для фронта, чтобы определить, какой текущий пользователь в системе */
    public UserDto getCurrentUser() {
        return mappingService.map(userContext.getUser(), UserDto.class);
    }

    /* при успешном логине обновляет сведения про юзера */
    public void login(String login) {
        AppUser user = getUserByLogin(login);
        user.setLastLoginDate(LocalDateTime.now());
        user.setIsActive(true);

        appUserDao.update(user);
    }

    public void logOut() {
        AppUser user = getUserByLogin(getCurrentUser().getLogin());
        user.setLastLoginDate(LocalDateTime.now());
        user.setIsActive(false);
        appUserDao.update(user);
    }

    public static void main(String[] args) {
        /* пример получения md5 hash для пассворд*/
        System.out.println(DigestUtils.md5DigestAsHex("password".getBytes())
                .toUpperCase());
    }
}