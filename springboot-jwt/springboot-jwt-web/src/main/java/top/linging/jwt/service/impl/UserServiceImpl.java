package top.linging.jwt.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.linging.jwt.mapper.UserMapper;
import top.linging.jwt.pojo.User;
import top.linging.jwt.service.UserService;

import java.util.List;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    /**
     * 登录
     * @param name
     * @return
     */
    @Override
    public User findUserByName(String name) {
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("name",name);
        return userMapper.selectOne(queryWrapper);
    }

    /**
     * 需要登录才能访问的api
     * @return
     */
    @Override
    public List<User> findAllUser() {
        return userMapper.selectList(null);
    }
}
