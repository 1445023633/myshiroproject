package com.example.demo.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
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
import org.apache.shiro.crypto.hash.SimpleHash;
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
	
//	(用于添加认证成功后的角色、权限等信息到shiro框架中的对象中,如果不加进去,index中将不会有角色。。
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
//        为当前用户的角色和权限放入认证管理中
        SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();
        authorizationInfo.addRoles(userRoles);
        authorizationInfo.addStringPermissions(userPermissions);
//		SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();
		return  authorizationInfo;
	}
	
	 /** 
     * 验证当前登录的Subject
     * LoginController.login()方法中执行Subject.login()时 执行此方法 ，生成了SimpleAuthenticationInfo对象后,
     * 然后进去令牌方法中进行判断,因为是与数据库中的密码进行匹配，所以要将获取到的user对象变成shiro框架中的SimpleAuthenticationInfo对象，
     * 所有的操作都是在shiro框架中进行，所以需要建立一些对象放入 shiro框架中。
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
        if(user==null) {
        	//没找到帐号
            throw new AccountException("没找到帐号11111111111");
        } 
//        ByteSource salt = ByteSource.Util.bytes(user.getSalt());
        //核心，将会把这个对象放到shiro框架中去，包括authcToken,
        //自己理解SimpleAuthenticationInfo是AuthenticationInfo的子类，UsernamePasswordToken是AuthenticationToken的子类 
        return new SimpleAuthenticationInfo(user, user.getPassword(),this.getClass().getName());//放入shiro.调用
	}
	
}
