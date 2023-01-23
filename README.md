# SpringSecurityBasicAuthFormAuthJWT
В данном проекте я научусь работать со Spring Security. Научусь делать Basic Auth, Form Auth и авторизацию с помощью JWT

----

## Как настроить аутентификацию на основе данных из БД

Чтобы иметь соединение с БД, нужно в файле проперти указать URL БД, драйвер для работы с БД, юзернейм и пароль

Чтобы Spring Security мог работать с БД нам нужно добавить зависиомсть `spring-boot-starter-data-jpa`

Также нужно создать Entity, который будет представлять таблицу пользователей

Ещё нужно создать репозиторий для работы с БД

Нужно создать собственный класс UserDetails и UserDetailsService

Далее нам необходимо мапить юзера из Entity в юзера из UserDetails

А после настроить менеджер аутентификации

И получается следующая цень взаимодействия:
1) Пользователь авторизуется
2) Вызывается менеджер аутентификации
3) Далее вызывается поставщик данных с настроенными UserDetailsService и PasswordEncoder
4) Поставщик (provider) получает пользователя через UserDetailsService внутри которого он преобразуется из Entity в UserDetails
5) Далее с помощью PasswordEncoder происходит сравнение паролей и если все отлично, то мы авторизуем пользователя

В данном случае у нас используется механизм сессии, поэтому в каждом запросе отправляем куки JSESSIONID