package top.linging.jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import top.linging.jwt.utils.CookieUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/router")
public class RouterController {

    @GetMapping("/toLogin")
    public String toLogin(HttpServletResponse response){
        return "jwt2";
    }
}
