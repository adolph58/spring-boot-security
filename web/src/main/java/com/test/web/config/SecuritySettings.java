package com.test.web.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 自定义的一个配置类
 * @ConfigurationProperties 设定配置参数的前缀部分为 securityconfig，定义的各个配置参数的意义如下：
 * logoutsuccssurl：用来定义退出成功的链接
 * permitall：用来定义允许访问的 URL 列表
 * deniedpage：用来设定拒绝访问的信息提示链接
 * urlroles：这是一个权限管理规则，是链接地址与角色权限的配置列表
 * 使用自定义配置参数后，可以在工程的配置文件 application.yml 中对安全管理进行集中配置，
 * 配置项
 * securityconfig:
 * 其中 urlroles 配置一个权限配置列表，这是我们设计的一种权限规则，列表中的每一个配置项用分号分隔，
 * 每一个配置项的等号左边是一个可以带上通配符的链接地址，等号右边是一个角色列表，角色之间用逗号分隔。
 * 每一个配置项表示包含等号左边字符串的链接地址，能够被等号右边的角色访问。
 * 这将要求我们的控制器设计链接地址时，必须遵循这一权限管理规则，这样只要使用一个简单的配置列表，
 * 就能够覆盖整个系统的权限管理策略。设计控制器链接地址的规则如下，它包含了系统增删改查的所有操作。
 */
@ConfigurationProperties(prefix="securityconfig")
public class SecuritySettings {
    private String logoutsuccssurl = "/logout";
    private String permitall = "/api";
    private String deniedpage = "/deny";
    private String urlroles;

    public String getLogoutsuccssurl() {
        return logoutsuccssurl;
    }

    public void setLogoutsuccssurl(String logoutsuccssurl) {
        this.logoutsuccssurl = logoutsuccssurl;
    }

    public String getPermitall() {
        return permitall;
    }

    public void setPermitall(String permitall) {
        this.permitall = permitall;
    }

    public String getDeniedpage() {
        return deniedpage;
    }

    public void setDeniedpage(String deniedpage) {
        this.deniedpage = deniedpage;
    }

    public String getUrlroles() {
        return urlroles;
    }

    public void setUrlroles(String urlroles) {
        this.urlroles = urlroles;
    }
}
