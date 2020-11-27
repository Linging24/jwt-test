package top.linging.jwt.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.mapper.Mapper;
import org.springframework.stereotype.Repository;
import top.linging.jwt.pojo.User;

@Repository
public interface UserMapper extends BaseMapper<User> {
}
