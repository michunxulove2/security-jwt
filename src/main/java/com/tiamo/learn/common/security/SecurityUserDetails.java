package com.tiamo.learn.common.security;

import com.tiamo.learn.model.pojo.SysUser;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collection;

/**
 * @ClassNameSecurityUserDetails
 * @Author小米
 * @Date2021/4/22 21:48
 * @Version 1.0
 **/
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
public class SecurityUserDetails extends SysUser implements UserDetails {

    private Collection<? extends GrantedAuthority> authorities;

    public SecurityUserDetails(String userName, Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        this.setLoginName(userName);
        String encode = new BCryptPasswordEncoder().encode("123");
        this.setLoginPwd(encode);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return getLoginPwd();
    }

    @Override
    public String getUsername() {
        return getLoginName();
    }

    /**
     * 账户是否过期
     *
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 是否禁用
     *
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 密码是否过期
     *
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否启用
     *
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
