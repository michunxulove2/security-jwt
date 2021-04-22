package com.tiamo.learn.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @ClassNameDemo
 * @Author小米
 * @Date2021/4/22 18:51
 * @Version 1.0
 **/
@Controller
@RequestMapping("/aa")
public class Demo {

    @RequestMapping("/bb")
    public void a() {
        System.out.println("11");
    }
}
