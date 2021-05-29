05SpringSecurity(安全)
引言
·在web开发中,安全第一位。目前,我们实现了使用过滤器Filter、拦截器Interceptor来实现Web开发中的安全
安全是一个功能性需求:否
·做网站、做后台 什么时候考虑安全====>设计之初
思考1:漏洞、隐私泄漏
思考2:架构一旦确定,就不好增加
·市面上比较知名的安全框架 shiro SpringSecurity 除了类不一样,名字不一样
功能十分相似:
[认证]: 用户名 密码 等的检查 
[授权]: 每个用户的权限不一样(以往是在拦截器里写大量的配置)
--权限:
    · 功能权限 用户-读者 作者 等等
    · 访问权限 有些页面有的人可以访问 有的人不能访问
    · 菜单权限 等等等等
    都可以使用大量的Filter Interceptor原生代码
MVC---Spring---SpringBoot---框架思想
 
准备工作
·新建工程 勾选web 导入thymeleaf包
 <dependency>
     <groupId>org.thymeleaf</groupId>
     <artifactId>thymeleaf-spring5</artifactId>
 </dependency> 
 <dependency>
     <groupId>org.thymeleaf.extras</groupId>
     <artifactId>thymeleaf-extras-java8time</artifactId>
 </dependency>  
导入素材
·全局配置文件中关闭thymeleaf缓存 设置项目虚拟路径
·编写Controller测试连通
[RequestMapping进行多个url映射]点进RequestMapping查看可以看到 他的路由value可以是一个数组
@RequestMapping({"","/index","index/"})

SpringSecurity通过AOP的思想:横切-配置类的思路
前端通过thymeleaf和SpringSecurity整合起来

SpringSecurity
·SpringSecurity是针对Spring项目的安全框架,也是SpringBoot底层安全模块默认的安全选型,可以实现强大的Web安全控制
[需要在pom.xml文件中引入spring-boot-starter-security模块]
·需要记住的几个类
--WebSecurityConfigurerAdapter:[需要继承这个类]自定义Security策略(适配器模式)
--AuthenticationManaterBuilder:自定义认证策略(建造者模式)
--[@Enable]WebSecurity[开启]WebSecurity模式
  @EnableXxx开启某个功能都是这种形式
·Spring Security两个主要目标: 认证 和 授权 (访问控制)
"认证"(Authentication)
"授权"(Authorization)
1.pom.xml中导入spring-boot-starter-security类
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
看到包下面有AOP的依赖,还有spring-security-config, 还有一个跟web相关的
2.创建config文件夹 创建配置[类SecurityConfig.java]
·查看官网:16. Java Configuration
https://docs.spring.io/spring-security/site/docs/5.3.0.M1/reference/htmlsingle/
@EnableWebSecurity  // 要使用这个注解开启功能(注入Spring)、继承这个类
public class SecurityConfig extends [WebSecurityConfigurerAdapter] {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
    }
}
接下来重写父类的方法 configure([HttpSecurity http])=====授权====>包括登录登出
·开始定制一些功能 
在WebSecurityConfigurerAdapter搜索protected void configure(HttpSecurity http) throws Exception参考下如何重写
详见SecurityConfig.java
 * The most basic configuration defaults to [automatically generating a login page] at
 * the URL "/login", redirecting to "/login?error" for authentication failure. The
 * details of the login page can be found on
// 绑定角色和页面之后 访问不在权限范围内的页面会报403错误
// 各种PasswordEncoder() 比如BCryptPasswordEncoder() 直接点进去就可以看到它实现的是那个接口
点击接口 在点击左侧行号栏就可以看到所有的密码编码器实现类了
接下来重写父类的方法 configure([AuthenticationManagerBuilder auth]) throws Exception====认证==绑定用户密码角色
在主页添加登出按钮[在semantic网上找登出按钮叫什么sign-out]
<!-- 注销按钮 这里连接为/logout security设置的登出才能生效
 Security设置之后默认登出的连接就是/logout -->
<a class="item" th:href="@{/logout}">
    <i class="sign-out icon"></i> 注销
</a>
[可以指定登出后默认跳转至哪个页面]

2.用户只能看到自己有权限看到的页面的实现[整合thymeleaf和security]
原来可以使用thymeleaf引擎的th:if="${session.user.role}"这种类似的形式实现,但是现在session里不存在
=====>现在整合thymeleaf和security
· pom.xml整合thymeleaf和security所需要的依赖(thymeleaf跟shiro也有整合包)
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-springsecurity[5]</artifactId>
    <version>3.0.4.RELEASE</version>
</dependency>
这样在thymeleaf中就可以使用security的一些操作[index页面]
·判断用户是不是已登录状态 <div sec:authorize="isAuthenticated()">
·取出用户的名字<span sec:authentication="name">
·判断用户是否有某个角色<div class="column" sec:authorize="hasRole('vip1')">
在SecurityConfig中可以关闭防止网站攻击的csrf
登录的话要直接访问/login页面 去security管理的登录页面登录

3.定制登录页面 接管Security的/login页面, 使自己的页面也有认证 授权等功能
http.formLogin();  [定制之后默认的/login无效了]
ctrl点进源码查看
* 	&#064;Override
* 	protected void configure(HttpSecurity http) throws Exception {
* 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
* 				.usernameParameter(&quot;username&quot;) // default is username
* 				.passwordParameter(&quot;password&quot;) // default is password
* 				.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
* 				.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
* 				.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
* 																		// with an HTTP
* 																		// post
## 以上都是Security默认的/login页面的配置 包括接收的参数等等(它相当于一个控制器)
http.formLogin().loginPage("/toLogin");
http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login")
/toLogin相当于用自己实现的登录页面给/login做一个包装[绑定/login页面的包装页面]
.loginProcessingUrl("/login")最后还是要将登录请求交给/login
[Security默认的登录处理器---
需要设置可以接收哪些参数 前端传入的user pwd 这里也要设置接收的是user pwd]
### /logout页面只有在SecurityConfig中关闭csrf或者以表单post的方式请求才能被过滤到

4.记住我功能
http.rememberMe();
plus:
在自定义的前端页面增加记住我复选框checkbox
                  // 接收自定义登录页面上的rememberMe参数
http.rememberMe().rememberMeParameter("rememberMe");
实现remember之后 cookie里会多个JSESSIONID
勾选记住我之后 cookie里会多个remember-me


                

