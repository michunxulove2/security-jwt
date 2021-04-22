package com.tiamo.learn.common.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * SecurityConfig配置里面不是有个方法是做真正的认证嘛，或者说从数据库拿信息，具体那认证信息的方法就是在这个方法里面。
 *
 * @ClassNameJwtUserDetailsService
 * @Author小米
 * @Date2021/4/22 21:52
 * @Version 1.0
 **/
@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String user) throws UsernameNotFoundException {
        System.out.println("JwtUserDetailsService:" + user);
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new SecurityUserDetails(user, authorityList);
    }
}
