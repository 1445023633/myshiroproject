package com.example.demo.action;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class ShiroSaltTest {
	

	 @RequestMapping(value="/ShiroSaltTest",method=RequestMethod.GET)
	  public String SaltTest(){
		 String source="123456";
		 String salt="Shiro";
		 
		 //加密次数
	        int hashIterations = 3;
	        
	        //调用 org.apache.shiro.crypto.hash.Md5Hash.Md5Hash(Object source, Object salt, int hashIterations)构造方法实现MD5盐值加密
	        Md5Hash mh=new Md5Hash(source,salt,hashIterations);
	        System.out.println(mh.toString());
	        
	        SimpleHash sh = new SimpleHash("md5", source, salt, hashIterations);
	        
	        SimpleHash sh2 = new SimpleHash("md5", source, salt, hashIterations);
	        System.out.println(sh.toString());
		        
			 String str="";
			 return str;
	 }
}
	 
