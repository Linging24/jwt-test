package top.linging.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import top.linging.jwt.pojo.User;
import top.linging.jwt.service.UserService;
import top.linging.jwt.utils.CookieUtils;
import top.linging.jwt.utils.JWTUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//@CrossOrigin(value = "*")
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Map<String,Object> login(@RequestParam("name") String username,
                                    HttpServletRequest request,
                                    HttpServletResponse response){
        int expireTime = 10;    //过期时间
        System.out.println(username);
        Map<String, String> payload = new HashMap<>();
        payload.put("name",username);
        String token = JWTUtils.createToken(payload,expireTime);
        Map<String, Object> map = new HashMap<>();
        if(token == null){
            map.put("status",false);
            map.put("msg","login fail");
            map.put("token","");
            return map;
        }
        CookieUtils.setCookie(request,response,"userToken",token,expireTime,"",true);
        map.put("status",true);
        map.put("msg","login ok");
        map.put("token",token);
        return map;
    }

    @GetMapping("/list")
    public List<User> findAllUser(){
        return userService.findAllUser();
    }
}
