package com.wq.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class RouterController {
    // 1.欢迎页面
    // RequestMapping进行多个url映射
    @RequestMapping({"","/","/index","index/"})
    public String index(){
        // index就在template下面
        return "index";
    }
    // 2.登录页面
    @RequestMapping("/toLogin")
    public String toLogin(){
        return "views/login";
    }
    // 3.1级vip可以进入的页面(通过一个参数搞定)
    @RequestMapping("/level1/{pageNum}")
    public String level1(@PathVariable("pageNum")int pageNum){
        return "views/level1/"+pageNum;
    }
    // 3.2级vip可以进入的页面(通过一个参数搞定)
    @RequestMapping("/level2/{pageNum}")
    public String level2(@PathVariable("pageNum")int pageNum){
        return "views/level2/"+pageNum;
    }
    // 3.3级vip可以进入的页面(通过一个参数搞定)
    @RequestMapping("/level3/{pageNum}")
    public String level3(@PathVariable("pageNum")int pageNum){
        return "views/level3/"+pageNum;
    }
    // 以上共计12个请求url
}
