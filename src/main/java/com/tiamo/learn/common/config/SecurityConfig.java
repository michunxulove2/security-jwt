package com.tiamo.learn.common.config;

import com.tiamo.learn.common.security.JwtAuthenticationEntryPoint;
import com.tiamo.learn.common.security.JwtAuthorizationTokenFilter;
import com.tiamo.learn.common.security.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 继承WebSecurityConfigurerAdapter
 * 这里面有三个方法需要重写
 * 1.configure  配置拦截
 * 2.exceptionHandling().authenticationEntryPoint(),主要配置如果没有凭证
 *   authorizeRequests()这个后边配置那些路径有需要什么权限
 *   permitAll(),及不需要权限就可以访问
 *   antMatchers(HttpMethod.OPTIONS, "/**")，是为了方便后面写前后端分离的时候前端过来的第一次验证请求 减少这种请求的时间和资源使用
 *   csrf().disable()是为了防止csdf攻击
 * 3
 *
 * @ClassNameSecurityConfig
 * @Author小米
 * @Date2021/4/22 20:23
 * @Version 1.0
 **/
@Configuration
@EnableWebSecurity //开启Security
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    JwtAuthorizationTokenFilter authenticationTokenFilter;

    /**
     * 认证
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoderBean());
    }

    /**
     * 拦截
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .authorizeRequests()
                .antMatchers("/aa/login").permitAll()
                .antMatchers("/haha").permitAll()
                .antMatchers("/sysUser/test").permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").anonymous()
                .anyRequest().authenticated()       // 剩下所有的验证都需要验证
                .and()
                .csrf().disable()                      // 禁用 Spring Security 自带的跨域处理
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // 定制我们自己的 session 策略：调整为让 Spring Security 不创建和使用 session

        http.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);//JWT验证

    }

    /**
     * 加密方式（可自定义加密）
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoderBean() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}

