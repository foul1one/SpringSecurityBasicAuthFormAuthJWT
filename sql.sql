create table springsecurity.users
(
    id    int auto_increment,
    email VARCHAR(255) not null unique,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    password_user VARCHAR(255) not null,
    role_user VARCHAR(25) default 'USER',
    status_user VARCHAR(25) default 'ACTIVE',
    primary key (id)
);

-- у админа пароль admin, у юзера пароль user
insert into users values
(1, 'admin@mail.com', 'admin', 'adminov', '$2a$12$xPiekKWAtWlU3rmox.qFTekmcHh9Sn6jaGdG/KejWxhG/33L/qUAm', 'ADMIN', 'ACTIVE'),
(2, 'user@mail.com', 'user', 'userov', '$2a$12$h8qlL/7JZ14KcPRHl9qhP.MJF0tENKi8/KVTemw8qqsj9Viw1GQMG', 'USER', 'BANNED');

