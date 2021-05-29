package com.wq.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 链式编程

    /***
     * 1.授权
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 首页所有人都可以访问, 但是功能页只有对应有权限的人才能访问
        // #########################加入请求授权的规则################################
//         http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
//         				.and()
//         				// sample logout customization
//         				.logout().deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
//         				.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
        // 0.设置角色访问页面的权限
        //           获得认证请求
        http.authorizeRequests()
                // 获得匹配器     / 代表首页    允许所有人访问
                .antMatchers("/").permitAll()
                // 可以进行多个设置       level1下的页面    只有vip1角色才能访问
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        // 1.登录
        // 绑定角色和页面之后 访问不在权限范围内的页面会报403错误
        // 若没有权限应该返回登录页面, 需要开启登录的页面
        // 为什么会进入/login页面 (点进下载源码查看)
        /**
         *  The most basic configuration defaults to [automatically generating a login page] at
         *  the URL "/login", redirecting to "/login?error" for authentication failure. The
         *  details of the login page can be found on
         *
         *  * 	&#064;Override
         * 	protected void configure(HttpSecurity http) throws Exception {
         * 	 http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
         * 	 		.usernameParameter(&quot;username&quot;) // default is username
         * 	 		.passwordParameter(&quot;password&quot;) // default is password
         * 	 		.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
         * 	 		.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
         * 	  		.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
         * 	 																		// with an HTTP
         * 	 																		// post
         * */
        // formLogin()默认的登录页面 loginPage()自己的login页面(定制之后默认的/login无效了)
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login")
        .usernameParameter("user")
        .passwordParameter("pwd");

        // 3.防止跨站请求网站攻击: get post
        // 主要只有以post的方式提交才可以生效 否则就要关闭csrf /logout页面才会被过滤到
        http.csrf().disable();

        // 2.登出
        // 	 * The following customization to log out when the URL "/custom-logout" is invoked.
        //	 * Log out will remove the cookie named "remove", not invalidate the HttpSession,
        //	 * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".

        //sample logout customization
        //            删除cookie                  销毁session
        //.logout().deleteCookies("remove").invalidateHttpSession(false)
        //                                         登出之后跳转到的页面
        //.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
        // 就算不设置这个http.logout(); Security也会占用这个/logout连接跳转至默认的退出页面
        // 可以指定登出后跳转至哪个页面
        http.logout().logoutSuccessUrl("/");

        // 4.开启记住我功能 session 和 cookie的实现 默认保存两周
        // (这都是在security默认的登录页面上)
        http.rememberMe().rememberMeParameter("rememberMe");
                        // 接收自定义登录页面上的rememberMe参数
    }


    /** 2.认证
     *  protected void configure(AuthenticationManagerBuilder auth) {
     *  auth
     *  // enable in memory based authentication with a user named
     *  // &quot;user&quot; and &quot;admin&quot;
     *  【在内存中的权限认证】     【user的名字】              【user的密码】                 【user的角色】          【and进行链式编程】
     *  .inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;).and()
     *  .withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
     * @param auth
     * @throws Exception
     * 报错:There is no PasswordEncoder mapped for the id "null"
     * 密码编码:在SpringSecurity 5.0+新增了很多加密方法,不能直接使用明文密码
     *
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 点进父类的源码查看设置
        //super.configure(auth);
        // 权限认证存取在内存中 用户访问时会去内存中读取
        //auth.inMemoryAuthentication()
        // 权限认证存储在数据库中 用户访问时会去数据库中读取
        //auth.jdbcAuthentication()           Spring5.0+不能直接使用明文密码 需要加密
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                //                                                         这里角色可以传入多个
                .withUser("wangqiang").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and().withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and().withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
