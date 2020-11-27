package top.linging.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.junit.Test;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

public class JWTTest {

    @Test
    public void test(){
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE, 7);
        //生成token
        String token = JWT.create()
                .withHeader(null)   //设置header，一般采用默认值
                .withClaim("name", "zhangsan")  //设置payload
                .withClaim("age", 18)
                .withClaim("sex", "girl")
                .withExpiresAt(instance.getTime())        //设置token的过期时间
                .sign(Algorithm.HMAC256("!@#QSDF@#@%￥……%")); //设置签名，采用HMAC256算法
        System.out.println(token);
    }

    @Test
    public void test2(){
        //验证token
        JWTVerifier build = JWT.require(Algorithm.HMAC256("!@#QSDF@#@%￥……%")).build();
        //验证token，验证失败会抛出异常
        DecodedJWT verify = build.verify("yJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzZXgiOiJnaXJsIiwibmFtZSI6InpoYW5nc2FuIiwiYWdlIjoxOH0.Cne13wAqFmRgmxgWOKgykGXVSfba5XjS-c4soh83QqQ");

        System.out.println(verify.getClaim("name").asString());
        System.out.println(verify.getClaim("age").asInt());
        System.out.println(verify.getClaim("sex").asString());
    }

    @Test
    public void test3(){
        Map<String, String> map = new HashMap<>();
        map.put("name","zhangsan");
        map.put("age","18");
        map.put("sex","man");
        String token = JWTUtils.createToken(map);
        System.out.println(token);

        System.out.println(JWTUtils.verifyJWT(token));
        String replaceToken = token.replace('6', 'c');
        System.out.println(JWTUtils.verifyJWT(replaceToken));

        Map<String, String> resMap = JWTUtils.decodeJWT(token);
        resMap.forEach((k,v)->{
            System.out.println("key=" + k + ",value="+v);
        });
    }
}
