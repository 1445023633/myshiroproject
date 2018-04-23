package com.example.demo.config;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import redis.clients.jedis.Jedis;

//令牌匹配
public class CredentialsMatcher extends SimpleCredentialsMatcher{
    private static final Logger log = LoggerFactory.getLogger(CredentialsMatcher.class);  

	
	 //集群中可能会导致出现验证多过5次的现象，因为AtomicInteger只能保证单节点并发    shiro自带 缓存
	//设置缓存对象
//    private Cache<String, AtomicInteger> lgoinRetryCache;  
    
   //设置缓存次数
//    private int maxRetryCount = 5;  
//    public void setMaxRetryCount(int maxRetryCount) {  
//        this.maxRetryCount = maxRetryCount;  
//    }  
//    //设置缓存的用户名 key?
//    private String lgoinRetryCacheName=null;  
    
//    //构造方法(不知道有用没。)
//	public CredentialsMatcher(CacheManager cacheManager,String lgoinRetryCacheName) {
//		this.lgoinRetryCacheName = lgoinRetryCacheName;  
//        lgoinRetryCache = cacheManager.getCache(lgoinRetryCacheName);
//	}
//    
	public CredentialsMatcher() {
		super();
	}
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		 UsernamePasswordToken utoken=(UsernamePasswordToken) token;
		 
		 String userName=utoken.getUsername();
		 System.out.println("userName:"+userName);
		 
	     //获得用户输入的密码:(可以采用加盐(salt)的方式去检验)
	     String inPassword = new String(utoken.getPassword());
	     System.out.println("inPassword"+inPassword);
	     
	     //对输如的密码进行加密3次md5
	     SimpleHash sh2 = new SimpleHash("md5", inPassword, "Shiro", 3);
	     System.out.println(sh2);
	     
	     //获得数据库中的密码  数据库中的密码保存的时候是通过sh2加密后存进去的
	     String dbPassword=(String) info.getCredentials();
	     System.out.println("dbPassword"+dbPassword);
	     boolean flage=sh2.toString().equals(dbPassword);
	     System.out.println("flage:"+flage);
	     
//		 利用redis缓存工具
	     Jedis jedis=new Jedis("localhost",6379);
	     int number=0;
	     if(!flage) {
	    	 if(jedis.get(userName)==null) {
	    		 System.out.println(jedis.get(userName));
	    		 //设置休眠60秒
	    	    jedis.set(userName,"1");
	    	    jedis.expire(userName, 60);
	    	 }else {
	    		 number=Integer.parseInt(jedis.get(userName));
	    		 number=number+1;
	    		 jedis.set(userName,String.valueOf(number));
	    		 jedis.expire(userName, 60);
	    	 }
	     }else {
	    	//解锁
//	    	String script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
//	    	number=Integer.parseInt(jedis.get(dbPassword));
//	    	Object result2 = jedis.eval(script, Collections.singletonList(dbPassword), Collections.singletonList(String.valueOf(number)));  
	    	if(jedis.get(userName)!=null) {
	    		 number=Integer.parseInt(jedis.get(userName));
	    		 if(number==2||number>2) {
//	    			throw new Exception("重复5次，锁");
	    			throw new DisabledAccountException("此帐号已经设置为禁止登录！");
	    		 }
	    		 jedis.del(userName);
	    	}
	     }
	     //进行密码的比对
//	     return this.equals(sh2.toString(),dbPassword);
	     return flage;
	}

	


		
}
