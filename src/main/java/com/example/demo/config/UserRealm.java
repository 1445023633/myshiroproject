package com.example.demo.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.demo.dao.Permession;
import com.example.demo.dao.User;
import com.example.demo.repository.IPermessionRepository;
import com.example.demo.repository.IUserRepository;
import com.example.demo.service.IUserService;

//身份验证领域
public class UserRealm extends AuthorizingRealm{
	
	//凭证匹配类
//	@Autowired
//	AuthCredential authCredential;
	
	//用户接口
	@Autowired
	private IUserRepository userRepository;
	
//	@Autowired
//	private IUserService  userService;
	
	@Autowired
	private IPermessionRepository permessionRepository;
	
//	//设置使用的是自己定义的凭证匹配类
//	public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {		// TODO Auto-generated method stub
//		super.setCredentialsMatcher(authCredential);
//	}
	
//	(用于获取认证成功后的角色、权限等信息
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
		//获取session中的用户
		User user=(User) principal.fromRealm(this.getClass().getName()).iterator().next();//获取session中的用户
		//角色集合
		List<String> userRoles = new ArrayList<String>(); 
		//权限集合
	    List<String> userPermissions = new ArrayList<String>();  
	    //从数据库中获取当前登录用户的详细信息  
//        User user = userRepository.findByUserName(currentLoginName);
        if(null != user){  
            //获取当前用户下拥有的所有角色列表
        	if(user.getUserName().contains(",")) {
        		String[]  roles=user.getRoles().split(",");
        		userRoles.addAll(Arrays.asList(roles));
        	}else {
        		userRoles.add(user.getRoles());
        	}
        	//获取当前所有权限集合
        	for(String role:userRoles) {
        		//获取角色对应
            	userPermissions.add(permessionRepository.findByRole(role).getPermissions());
        	}
        }else{  
            throw new AuthorizationException("找不到该用户名对应的用户");  
        }  
        //为当前用户的角色和权限放入认证管理中
        SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();
        authorizationInfo.addRoles(userRoles);
        authorizationInfo.addStringPermissions(userPermissions);
		return authorizationInfo;
	}
	
	 /** 
     * 验证当前登录的Subject
     * LoginController.login()方法中执行Subject.login()时 执行此方法 
     */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken) throws AuthenticationException {
		System.out.println("###【开始认证[SessionId]】"+SecurityUtils.getSubject().getSession().getId());
		UsernamePasswordToken token = (UsernamePasswordToken) authcToken;
		//获取到的用户名和密码
		String username = token.getUsername();
        String password = String.valueOf(token.getPassword());
        //对用户名和密码进行加密
//        Map<String, Object> map = new HashMap<String, Object>();
//        map.put("nickname", username); 
        User user = userRepository.findByUserName(username);
        if(user == null) {
            throw new UnknownAccountException();//没找到帐号
        } 
        return new SimpleAuthenticationInfo(user, user.getPassword(),this.getClass().getName());//放入shiro.调用
	}
}
