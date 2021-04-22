package com.tiamo.learn.model.pojo;

import com.baomidou.mybatisplus.annotation.TableField;
import lombok.Data;

/**
 * @ClassNameSysUser
 * @Author小米
 * @Date2021/4/22 22:12
 * @Version 1.0
 **/
@Data
public class SysUser {

    @TableField("id")
    private Integer id;

    @TableField("login_name")
    private String loginName;

    @TableField("login_pwd")
    private String loginPwd;
}
