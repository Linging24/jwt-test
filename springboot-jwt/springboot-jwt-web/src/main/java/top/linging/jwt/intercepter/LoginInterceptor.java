package top.linging.jwt.intercepter;


import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import top.linging.jwt.utils.CookieUtils;
import top.linging.jwt.utils.JWTUtils;
import top.linging.jwt.utils.JsonUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class LoginInterceptor implements HandlerInterceptor {

    /**
     * 获取requestHeader中的token
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("拦截诶器中...............");
        //获取requestHeader中的token
        String token = CookieUtils.getCookieValue(request,"userToken");
        //返回结果
        Map<String, Object> map = new HashMap<>();
        //验证token失败
        if(token == null || !JWTUtils.verifyJWT(token)) {
            map.put("status",false);
            map.put("msg","login fail");
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().println(JsonUtil.mapToJson(map));
            return false;
        }
        //放行
        System.out.println("成功.....");
        return true;
    }
}
