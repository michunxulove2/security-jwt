package com.tiamo.learn.controller;

import com.tiamo.learn.common.security.JwtTokenUtil;
import com.tiamo.learn.model.pojo.SysUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassNameDemo
 * @Author小米
 * @Date2021/4/22 18:51
 * @Version 1.0
 **/
@RestController
@RequestMapping("/aa")
public class Demo {

    @Autowired
    @Qualifier("jwtUserDetailsService")
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public String login(@RequestBody SysUser sysUser){
        final UserDetails userDetails = userDetailsService.loadUserByUsername(sysUser.getLoginName());
        final String token = jwtTokenUtil.generateToken(userDetails);
        return token;
    }

    @RequestMapping("/bb")
    public void a() {
        System.out.println("11");
    }
}
