package top.linging.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT工具类
 */
public class JWTUtils {

    //随机盐，随机设置
    private final static String secret = "$%#$%%^FSDFDS@#$@ASDdfg";

    /**
     * 根据提供的k-v进行生成token
     * @param payload k-v信息
     * @return token
     */
    public static String createToken(Map<String,String> payload) {
        //设置7天为过期时间
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE,7);
        String token = null;
        try{
            //创建Builder对象
            JWTCreator.Builder builder = JWT.create().withHeader(null); //header
            //payload
            payload.forEach((k,v)->{
                builder.withClaim(k,v);
            });
            builder.withExpiresAt(instance.getTime());      //过期时间
            token = builder.sign(Algorithm.HMAC256(secret));    //签名
        }catch (JWTCreationException e){
            System.out.println("构建token异常，请检查签名是否合法...");
        }
        return token;
    }

    /**
     * 验证token是否合法
     * @param token
     * @return false:验证失败  true：验证合法
     */
    public static boolean verifyJWT(String token){
        try{
            JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
        }catch (JWTVerificationException e){
            return false;
        }
        return true;
    }


    /**
     * 获取token的数据
     * @return map
     */
    public static Map<String,String> decodeJWT(String token){
        Map<String,String> map = new HashMap<>();
        try{
            DecodedJWT verify = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
            Map<String, Claim> claims = verify.getClaims();
            claims.forEach((k,v)->{
                map.put(k,v.asString());
            });
            return map;
        }catch (JWTVerificationException e){
            return null;
        }
    }
}
