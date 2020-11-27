package top.linging.jwt;

import org.junit.Test;
import org.openjdk.jol.info.ClassLayout;
import top.linging.jwt.pojo.LockObj;

public class LockTest {


    @Test
    public void test2(){
        LockObj lockObj = new LockObj();
        System.out.println(ClassLayout.parseInstance(lockObj).toPrintable());
    }
}
