package com.tiamo.learn.common.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @ClassNameJwtAuthenticationEntryPoint
 * @Author小米
 * @Date2021/4/22 22:10
 * @Version 1.0
 **/
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        System.out.println("JwtAuthenticationEntryPoint:"+e.getMessage());
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,"没有凭证");
    }
}
