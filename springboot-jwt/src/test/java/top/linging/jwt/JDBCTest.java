package top.linging.jwt;

import org.junit.Test;

import java.sql.*;

public class JDBCTest {

    String driver = "com.mysql.cj.jdbc.Driver";
    String url = "jdbc:mysql://localhost:3306/student?characterEncoding=UTF-8&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
    String username = "root";
    String password = "123456";

    @Test
    public void test() throws ClassNotFoundException, SQLException {
        // 1.加载驱动
        Class.forName(driver);
        // 2.获取连接
        Connection conn = DriverManager.getConnection(url, username, password);
        // 3.定义sql
        String sql = "select *from user";
        // 4.获取preparedStatement对象
        PreparedStatement prep = conn.prepareStatement(sql);
        // 5.占位符设置参数
        //...set
        // 6.执行sql获取结果集
        ResultSet res = prep.executeQuery();
        // 7.遍历结果集
        while(res.next()){
            int id = res.getInt(1);
            String name = res.getString(2);
            System.out.println("id="+id + ",name="+name);
        }
        // 8.关闭资源
        prep.close();
        conn.close();
    }

}
