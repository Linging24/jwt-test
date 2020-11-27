package top.linging.jwt;

import org.apache.ibatis.annotations.Mapper;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("top.linging.jwt.mapper")
public class SpringbootJwtWebApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringbootJwtWebApplication.class, args);
    }

}
