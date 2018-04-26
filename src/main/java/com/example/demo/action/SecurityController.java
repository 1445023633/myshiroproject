package com.example.demo.action;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.demo.dao.User;

@Controller
public class SecurityController {
	private static final Logger logger = LoggerFactory.getLogger(SecurityController.class);
	
//	@RequiresRoles("ADMIN")
//    @RequestMapping(value="/index",method=RequestMethod.GET)
//    public String index(Model model){
//        String userName = (String) SecurityUtils.getSubject().getPrincipal();
//        model.addAttribute("username", userName);
//        return "index";
//    }
//    @RequestMapping(value="",method=RequestMethod.GET)
//    public String defaultIndex(Model model){
//        String userName = (String) SecurityUtils.getSubject().getPrincipal();
//        model.addAttribute("username", userName);
//        return "index";
//    }
	
	//访问登录页面
    @RequestMapping(value="/login",method=RequestMethod.GET)
    public String loginForm(Model model){
        model.addAttribute("user", new User());
        return "login";
    }
    
    //页面用户登录
    @RequestMapping(value="/login",method=RequestMethod.POST)
    public String login(@Valid User user,BindingResult bindingResult,RedirectAttributes redirectAttributes){
    	//绑定到shiro?
    	if(bindingResult.hasErrors()){
            return "login";
        }
        String username = user.getUserName();
        System.out.println(username);
        //生成shiro中需要验证的对象
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUserName(), user.getPassword());
        //处理session,防止重复登录
        SessionsSecurityManager securityManager = (SessionsSecurityManager) SecurityUtils.getSecurityManager();
        DefaultSessionManager sessionManager = (DefaultSessionManager) securityManager.getSessionManager();
        Collection<Session> sessions = sessionManager.getSessionDAO().getActiveSessions();//获取当前已登录的用户session列表
        for (Session session : sessions) {
            //清除该用户以前登录时保存的session
//            IotdUserEntity en=(IotdUserEntity)(session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY));
//            String phone=en.getPhone();
            //如果和当前session是同一个session，则不剔除
            if (SecurityUtils.getSubject().getSession().getId().equals(session.getId())) {
                break;
            }else if(session.getAttribute(username)!=null){
                sessionManager.getSessionDAO().delete(session);
            } 
        }
        //获取当前的Subject（shiro框架中）  所有的与shiro框架交互的都是通过Subject 
        Subject currentUser = SecurityUtils.getSubject();  
        try {  
            //在调用了login方法后,SecurityManager会收到AuthenticationToken,并将其发送给已配置的Realm执行必须的认证检查  
            //每个Realm都能在必要时对提交的AuthenticationTokens作出反应  
            //所以这一步在调用login(token)方法时,它会走到MyRealm.doGetAuthenticationInfo()方法中,具体验证方式详见此方法  
            logger.info("对用户[" + username + "]进行登录验证..验证开始");  
            //将进入到shiro框架中调用安全管理器进行相应的操作
            currentUser.login(token);
            //验证是否登录成功  
            if(currentUser.isAuthenticated()){  
                logger.info("用户[" + username + "]登录认证通过(这里可以进行一些认证通过后的一些系统参数初始化操作)");  
                SecurityUtils.getSubject().getSession().setAttribute(username,user.getPassword());
                //需要清除，否则登录成功后不需要密码也能进来。什么都是shiro管理。坑的地方
                token.clear();          
                return "/index";
            }else{  
                token.clear();  
                return "redirect:/login";
            }
        }catch(UnknownAccountException uae){  
            logger.info("对用户[" + username + "]进行登录验证..验证未通过,未知账户");  
            redirectAttributes.addFlashAttribute("message", "未知账户");  
        }catch(IncorrectCredentialsException ice){  
            logger.info("对用户[" + username + "]进行登录验证..验证未通过,错误的凭证");  
            redirectAttributes.addFlashAttribute("message", "密码不正确");  
        }catch(LockedAccountException lae){  
            logger.info("对用户[" + username + "]进行登录验证..验证未通过,账户已锁定");  
            redirectAttributes.addFlashAttribute("message", "账户已锁定");  
        }catch(ExcessiveAttemptsException eae){  
            logger.info("对用户[" + username + "]进行登录验证..验证未通过,错误次数过多");  
            redirectAttributes.addFlashAttribute("message", "用户名或密码错误次数过多");  
        }catch(AuthenticationException ae){  
            //通过处理Shiro的运行时AuthenticationException就可以控制用户登录失败或密码错误时的情景  
            logger.info("对用户[" + username + "]进行登录验证..验证未通过,堆栈轨迹如下");  
            ae.printStackTrace();  
            redirectAttributes.addFlashAttribute("message", "用户名或密码不正确");  
        }  
       return null;
    }
    
    
    @RequestMapping(value="/logOut",method=RequestMethod.POST)
    public String logOut(HttpSession session) {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
//        session.removeAttribute("user");
        return "login";
    }

//
//    @RequestMapping("/pages/403")
//    public String unauthorizedRole(){
//        logger.info("------没有权限-------");
//        return "403";
//    }
//    
    //1.必须将它改成加密模式。使用md5加密,ok
    //2.如何登出。 ok
    //3.如何限制登录失败次数，并设置上锁时间 CredentialsMatcher里面检查，记录登录次数是最简单的做法。
    //4.如何设置缓存    继承HashedCredentialsMatcher，加入缓存， Ehcache来记录用户登录次数的计数，在每次验证用户名密码之前先验证用户名尝试次数，
    //如果超过5次就抛出尝试过多异常，否则验证用户名密码，验证成功把尝试次数清零，不成功则直接退出。
    
    //缓存采用redis的缓存,计数也用key,value并设置存活时间即可来执行。如果计数已经是5次则抛出异常，
    
    //缓存有问题，另外登录成功后，再次输入密码虽然错误但是也能进去。。。。

}
