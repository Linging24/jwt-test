package top.linging.jwt.service;

import top.linging.jwt.pojo.User;

import java.util.List;

public interface UserService{
    User findUserByName(String name);

    List<User> findAllUser();

}
