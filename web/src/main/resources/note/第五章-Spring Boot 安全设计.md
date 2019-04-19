# 第五章 Spring Boot 安全设计
Web 引用的安全管理，主要包括两个方面的内容：一方面是用户身份认证，即用  
户登录的设计；另一方面是用户授权，即一个用户在一个应用系统中能够执行哪  
些操作的权限管理。权限管理的设计一般使用角色来管理，即给一个用户赋予哪  
些角色，这个用户就具有哪些权限。本章主要使用 spring-cloud-security 来进  
行安全管理设计。

## 5.1 依赖配置管理
为了方便地使用 spring-cloud-security，将使用 Spring Cloud 的 Maven 依赖，  
``` 
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-security</artifactId>
</dependency>
```

## 5.2 安全策略配置
关于系统的安全管理及各种设计，Spring Security 已经大体上都实现了，只需要  
进行一些配置和引用，就能够正常使用。  
详细配置见 SecurityConfiguration 类 void configure(HttpSecurity http) 方法

### 5.2.1 权限管理规则
SecuritySettings 类是自定义的一个配置类  
logoutsuccssurl：用来定义退出成功的链接  
permitall：用来定义允许访问的 URL 列表  
deniedpage：用来设定拒绝访问的信息提示链接  
urlroles：这是一个权限管理规则，是链接地址与角色权限的配置列表  

代码清单 5-3 自定义配置类
```
@ConfigurationProperties(prefix="securityconfig")
public class SecuritySettings {
    private String logoutsuccssurl = "/logout";
    private String permitall = "/api";
    private String deniedpage = "/deny";
    private String urlroles;
```
urlroles：这是一个权限管理规则，是链接地址与角色权限的配置列表  
使用自定义配置参数后，可以在工程的配置文件 application.yml 中对安全管理  
进行集中配置，如代码清单 5-4 所示

代码清单 5-4 使用自定义的 securityconfig 配置
```
securityconfig:
  logoutsuccssurl: /
  permitall: /rest/**,/bbs**
  deniedpage: /deny
  urlroles: /**/new/** = admin;
            /**/edit/** = admin,editor;
            /**/delete/** = admin
```
其中 urlroles 配置一个权限配置列表，这是我们设计的一种权限规则，列表中  
的每一个配置项用分号分隔，每一个配置项的等号左边是一个可以带上通配符的  
链接地址，等号右边是一个角色列表，角色之间用逗号分隔。每一个配置项表示  
包含等号左边字符串的链接地址，能够被等号右边的角色访问。  

这将要求我们的控制器设计链接地址时，必须遵循这一权限管理规则，这样只要  
使用一个简单的配置列表，就能够覆盖整个系统的权限管理策略。设计控制器链  
接地址的规则如下，它包含了系统增删改查的所有操作。

使用这种规则之后，再来看看代码清单 5-4 中 urlroles 的权限配置，这里只需要  
简单的三个配置项，就已经完成了对一个应用系统所有权限的管理配置了。其中，  
新建操作只有 manage、admin 两个角色有权限，修改操作和删除操作只有 admin  
这个角色有权限，至于没有在权限管理列表中配置的查看操作，因为没有限定角色  
访问，所以它能被所有用户访问。

### 5.2.3 防攻击策略
因为 Spring Security 的跨站请求伪造（cross-site request forgery，CSRF）即  
阻止跨站请求伪造攻击的功能很完善，所以使用 Spring Security 之后，对于新建、  
修改和删除等操作，必须进行特殊的处理，才能正常使用。这要求在所有具有上面  
操作请求的页面上提供如下代码片段，因为我们的页面设计使用了 Thymeleaf 模板，  
所以只要在 layout.html 的页头上加入下面两行代码即可，layout.html 是所有页面  
都会用到的一个页面文件。
```
 <meta name="_csrf" th:content="${_csrf.token}"/>
 <meta name="_csrf_header" th:content="${_csrf.headerName}"/>
```
还要在 layout.html 中引用脚本文件 public.js，然后在 public.js 中增加一个  
函数，如代码清单 5-6 所示。这样做的意思是，在表单提交时放入一个 token，  
服务端验证该 token 是否有效，只允许有效的 token 请求，否则拒绝当前操作。  
这样就能够很好地起到防御 CSRF 攻击的目的。

代码清单 5-6 阻止 CSRF 攻击策略
```
$(function () {
    var token = $("meta[name='_csrf']").attr("content");
    var header = $("meta[name='_csrf_header']").attr("content");
    $(document).ajaxSend(function(e, xhr, options) {
        xhr.setRequestHeader(header, token);
    });
});
```

如果要对第三方开放接口，上面的方法就不适用了，这时只能对特定的 URL 使用排除  
CSRF 保护的方法来实现。代码清单 5-7 对指定的 URL 排除对其进行 CSRF 的保护。

代码清单 5-7 排除 CSRF 保护策略
```
public class CsrfSecurityRequestMatcher implements RequestMatcher {
    protected Log log = LogFactory.getLog(getClass());
    private Pattern allowedMethods = Pattern
            .compile("^(GET|HEAD|TRACE|OPTIONS)$");
    /**
     * 需要排除的url列表
     */
    private List<String> execludeUrls;

    @Override
    public boolean matches(HttpServletRequest request) {
        if (execludeUrls != null && execludeUrls.size() > 0) {
            String servletPath = request.getServletPath();
            for (String url : execludeUrls) {
                if (servletPath.contains(url)) {
                    log.info("++++"+servletPath);
                    return false;
                }
            }
        }
        return !allowedMethods.matcher(request.getMethod()).matches();
    }

   ……
}
```
然后在配置类中，加入需要排除阻止 CSRF 攻击的链接列表，如代码清单 5-8 所示，  
只要链接地址中包含“/rest”字符串，就将对其忽略 CSRF 保护策略。

代码清单 5-8 在安全配置类中加入需要排除 CSRF 保护的列表
```
private CsrfSecurityRequestMatcher csrfSecurityRequestMatcher(){
        CsrfSecurityRequestMatcher csrfSecurityRequestMatcher = new CsrfSecurityRequestMatcher();
        List<String> list = new ArrayList<String>();
        list.add("/rest/");
        csrfSecurityRequestMatcher.setExecludeUrls(list);
        return csrfSecurityRequestMatcher;
    }
```

### 5.2.4 记住登录状态
SecurityConfiguration 类中有一行配置：rememberMe().tokenValiditySeconds  
(86400).tokenRepository(tokenRepository())，它是用来记住用户登录状态的一个  
配置，其中 86400 指定记住的实践秒数，即为 1 天实践。为了实现这个功能，需要  
将一个用户的登录令牌信息保存在数据库中，这需要在配置类中指定连接数据库的数  
据源，如代码清单 5-9 所示。

代码清单 5-9 指定保存登录用户 token 的数据源
``` 
@Autowired @Qualifier("dataSource")
private DataSource dataSource;

@Bean
    public JdbcTokenRepositoryImpl tokenRepository(){
        JdbcTokenRepositoryImpl jtr = new JdbcTokenRepositoryImpl();
        jtr.setDataSource(dataSource);
        return jtr;
    }
    
```

同时，还应该在数据库中增加一个数据表 persistent_logins，这个表结构的定义是  
由 Spring Security 提供的，使用一个实体来实现，这样做的目的只是为了在系统  
启动时能够创建这个表结构而已，如代码清单 5-10 所示，它用来保存用户名、令牌  
和最后登录时间等信息。

代码清单 5-10 记住用户登录状态的实体建模
``` 
@Entity
@Table(name = "persistent_logins")
public class PersistentLogins implements java.io.Serializable{
    @Id
    @Column(name = "series", length = 64, nullable = false)
    private String series;
    @Column(name = "username", length = 64, nullable = false)
    private String username;
    @Column(name = "token", length = 64, nullable = false)
    private String token;
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "last_used", nullable = false)
    private Date last_used;
    ……
}
```

## 5.3 登录认证设计
完成上面的安全策略配置之后，打开受保护的页面和链接时，就会引导用户到登录  
页面上输入用户名和密码验证用户身份。如果在安全配置中没有指定登录页面 URL，  
Spring Security 就调用其默认的登录页面。只是，Spring Security 的登录页面  
设计很简单，不适合于一般的 Web 应用的登录设计。除了登录页面，Spring Security  
对于用户身份验证同样也已经实现了，只需要加以引用即可。

### 5.3.1 用户实体建模
实体类包括用户、部门和角色三个对象，它们的关系是，一个用户只能属于一个部门，  
一个用户可以拥有多个角色，这非常适合本章的实例。除了部门和角色，用户实体的  
属性必须做些调整，以适合本章实例的要求，如代码清单 5-11 所示，即增加了邮箱、  
性别和密码等几个属性，其他基本相同

代码清单 5-11 用户实体建模
``` 
@Entity
@Table(name = "user")
public class User implements java.io.Serializable{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;
    private Integer sex;
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date createdate;
    private String password;

    @ManyToOne
    @JoinColumn(name = "did")
    @JsonBackReference
    private Department department;

    @ManyToMany(cascade = {}, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "roles_id")})
    private List<Role> roles;
    ……
}
```
另外，在用户实体的持久化方面，也增加了几个方法以便能适用本章实例的要求，  
如代码清单 5-12 所示。其中 User findByName(String name) 就是登录时使用用户  
名来查询用户的信息。

代码清单 5-12 用户实体持久化接口
``` 
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("select t from User t where t.name =?1 and t.email =?2")
    User findByNameAndEmail(String name, String email);

    @Query("select t from User t where t.name like :name")
    Page<User> findByName(@Param("name") String name, Pageable pageRequest);

    User findByName(String name);
}
```

### 5.3.2 用户身份验证
在安全配置类的定义中，使用了如代码清单 5-13 所示的配置，用来调用我们自定义  
的用户认证 CustomUserDetailsService，并且指定了使用密码的加密算法为  
BCryptPasswordEncoder，这是 Spring Security 官方推荐的加密算法，比 MD5 算法  
的安全性更高。

代码清单 5-13 安全配置类引用 CustomUserDetailsService
``` 
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
        //remember me
        auth.eraseCredentials(false);
    }
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

如代码清单 5-14 所示，CustomUserDetailsService 实现了 Spring Security 的
UserDetailsService，重载了UserDetails loadUserByUsername(String userName)，  
并返回自定义的 SecurityUser，通过这个 SecurityUser 来完成用户的身份认证。  
其中，loadUserByUsername 调用了用户资源库接口的 findByName 方法，取得登录  
用户的详细信息。

代码清单 5-14 CustomUserDetailsService 定义
``` 
@Component
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepository.findByName(userName);
        if (user == null) {
            throw new UsernameNotFoundException("UserName " + userName + " not found");
        }
        return new SecurityUser(user);
    }
}
```
SecurityUser 继承于实体对象 User，并实现了 Spring Security 的 UserDetails，  
同时重载了 getAuthorities()，用来取得为用户分配的角色列表，用户后面的权限  
验证，它的实现如代码清单 5-15 所示。

代码清单 5-15 SecurityUser 定义
``` 
public class SecurityUser extends User implements UserDetails {

    private static final long serialVersionUID = 1L;
    public SecurityUser(User user) {
        if(user != null)
        {
            this.setId(user.getId());
            this.setName(user.getName());
            this.setEmail(user.getEmail());
            this.setPassword(user.getPassword());
            this.setSex(user.getSex());
            this.setCreatedate(user.getCreatedate());
            this.setRoles(user.getRoles());
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        List<Role> roles = this.getRoles();
        if(roles != null)
        {
            for (Role role : roles) {
                SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getName());
                authorities.add(authority);
            }
        }
        return authorities;
    }
    ……
}
```

### 5.3.3 登录界面设计
首先创建一个登录控制器，编写如代码清单 5-16 所示的代码，这个控制器很简单，  
它仅仅返回一个页面的调用，页面的设计文件是 login.html。

代码清单 5-16 登录控制器
``` 
@Controller
public class LoginController {
    @RequestMapping("/login")
    public String login(){
        return "login";
    }
}
```
登录界面的设计在页面文件 login.html 中完成。表单中设置了用户、密码和验证码  
等输入框，最终使用 POST 方式提交，提交的链接地址是 /login，这将请求 Spring  
Security 的内部方法。

### 5.3.4 验证码验证
自己实现  
imagecode 方法是一个生成图形验证码的请求，checkcode 方法实现了对这个图形验  
证码的验证。从验证码的生成到验证的过程中，验证码是通过 Session 来保存的，并  
且设定一个验证码的最长有效时间为 5 分钟。验证码的规则是从 0 - 9 的数字中，  
随机产生一个 4 位数，并增加一些干扰元素，最终组合成为一个图形输出。

代码清单 5 - 18 验证码验证
``` 
    @RequestMapping(value = "/images/imagecode")
    public String imagecode(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        OutputStream os = response.getOutputStream();
        Map<String,Object> map = ImageCode.getImageCode(60, 20, os);

        String simpleCaptcha = "simpleCaptcha";
        request.getSession().setAttribute(simpleCaptcha, map.get("strEnsure").toString().toLowerCase());
        request.getSession().setAttribute("codeTime",new Date().getTime());

        try {
            ImageIO.write((BufferedImage) map.get("image"), "JPEG", os);
        } catch (IOException e) {
            return "";
        }
        return null;
    }
    
    @RequestMapping(value = "/checkcode")
        @ResponseBody
        public String checkcode(HttpServletRequest request, HttpSession session)
                throws Exception {
            String checkCode = request.getParameter("checkCode");
            Object cko = session.getAttribute("simpleCaptcha") ; //验证码对象
            if(cko == null){
                request.setAttribute("errorMsg", "验证码已失效，请重新输入！");
                return "验证码已失效，请重新输入！";
            }
    
            String captcha = cko.toString();
            Date now = new Date();
            Long codeTime = Long.valueOf(session.getAttribute("codeTime")+"");
            if(StringUtils.isEmpty(checkCode) || captcha == null ||  !(checkCode.equalsIgnoreCase(captcha))){
                request.setAttribute("errorMsg", "验证码错误！");
                return "验证码错误！";
            }else if ((now.getTime()-codeTime)/1000/60>5){//验证码有效时长为5分钟
                request.setAttribute("errorMsg", "验证码已失效，请重新输入！");
                return "验证码已失效，请重新输入！";
            }else {
                session.removeAttribute("simpleCaptcha");
                return "1";
            }
        }
    
```


## 5.4 权限管理设计
用户通过身份认证，成功登录系统后，就要开始检查用户访问资源的权限，如果用户  
没有权限访问，将会阻止用户访问受保护的资源，并给出错误提示信息

### 5.4.1 权限管理配置
在安全配置类中，定义了几个类,实现自定义的权限检查判断及管理的功能，各个类  
的意义如下：
- CustomFilterSecurityInterceptor：权限管理过滤器
- CustomAccessDecisionManager：权限管理决断器
- CustomSecurityMetadataSource：权限配置资源管理器

其中，过滤器在系统启动时开始工作，并同时导入资源管理器和权限决断器，对用户  
访问的资源进行管理。权限决断器对用户访问的资源与用户拥有的角色权限进行对比，  
以此来判断一个用户是否对一个资源具有访问权限。

## 5.5 根据权限设置链接
对于权限管理，我们可能希望，在一个用户访问的界面中，不是等用户单击了一个超  
链接之后，才来判断用户有没有这个权限（虽然这种设计是必须的），而是按照用户  
拥有的权限来设置一个用户可以访问的超链接。这样的设计对于用户体验来说，显得  
更加友好。

以管理后台中用户管理的例子来说明如何实现根据权限来设置链接。如代码清单 5-23  
所示，在打开用户管理主页的控制器中，读取了当前用户的权限配置，然后根据这个  
用户的权限列表来判断这个用户是否拥有新建、修改和删除等权限，最后把这些权限  
通过变量传给页面，由页面负责根据权限来设置用户可用的超链接。其中，newrole、  
editrole 和 deleterole 分别表示新建、修改和删除权限的判断值。

代码清单 5 - 23 在控制器中获取用户权限
``` 
 @Value("${securityconfig.urlroles}")
    private String urlroles;

    @RequestMapping("/index")
    public String index(ModelMap model, Principal user) throws Exception{
        Authentication authentication = (Authentication)user;
        List<String> userroles = new ArrayList<>();
        for(GrantedAuthority ga : authentication.getAuthorities()){
            userroles.add(ga.getAuthority());
        }

        boolean newrole=false,editrole=false,deleterole=false;
        if(!StringUtils.isEmpty(urlroles)) {
            String[] resouces = urlroles.split(";");
            for (String resource : resouces) {
                String[] urls = resource.split("=");
                if(urls[0].indexOf("new") > 0){
                    String[] newroles = urls[1].split(",");
                    for(String str : newroles){
                        str = str.trim();
                        if(userroles.contains(str)){
                            newrole = true;
                            break;
                        }
                    }
                }else if(urls[0].indexOf("edit") > 0){
                    String[] editoles = urls[1].split(",");
                    for(String str : editoles){
                        str = str.trim();
                        if(userroles.contains(str)){
                            editrole = true;
                            break;
                        }
                    }
                }else if(urls[0].indexOf("delete") > 0){
                    String[] deleteroles = urls[1].split(",");
                    for(String str : deleteroles){
                        str = str.trim();
                        if(userroles.contains(str)){
                            deleterole = true;
                            break;
                        }
                    }
                }
            }
        }

        model.addAttribute("newrole", newrole);
        model.addAttribute("editrole", editrole);
        model.addAttribute("deleterole", deleterole);

        model.addAttribute("user", user);
        return "user/index";
    }
```

在用户管理的主页视图中有一个“新增”超链接，可以通过控制器传递过来的 newrole  
值来判断这个用户对这个链接有没有权限，从而决定这个链接能不能显示出来，提供给  
用户使用，代码如下：
``` 
<div class="newBtnBox" th:if="${newrole}">
    <a id="addUserInf" class="blueBtn-62X30" href="javascript:void(0)">新增</a>
</div>
```

而对于修改和删除的权限，因为页面的数据是从 js 中生成的，所以可以在生成用户列表  
的程序段中判断 editrole 和 deleterole，从而决定是否提供这两个功能的链接，如代码  
清单 5-24 所示。

代码清单 5-24 在 js 中根据用户权限设置链接
``` 
//填充分页数据
function fillData(data){
    var editrole = $("#editrole").val();
    var deleterole = $("#deleterole").val();

    var $list = $('#tbodyContent').empty();
    $.each(data,function(k,v) {
        var html = "";
        html += '<tr> ' +
            '<td>' + (v.id == null ? '' : v.id) + '</td>' +
            '<td>' + (v.name == null ? '' : v.name) + '</td>' +
            '<td>' + (v.email == null ? '' : v.email) + '</td>' +
            '<td>' + (v.createdate == null ? '' : getSmpFormatDateByLong(v.createdate, true)) + '</td>';
        html += '<td><a class="c-50a73f mlr-6" href="javascript:void(0)" onclick="showDetail(\'' + v.id + '\')">查看</a>';

        if (editrole == 'true')
            html += '<a class="c-50a73f mlr-6" href="javascript:void(0)" onclick="edit(\'' + v.id + '\')">修改</a>';

        if(deleterole == 'true')
            html += '<a class="c-50a73f mlr-6" href="javascript:void(0)" onclick="del(\''+ v.id+'\')">删除</a>';

        html +='</td></tr>' ;

        $list.append($(html));
    });
}
```

其中的“修改”和“删除”权限的判断值，即代码中的 editrole 和 deleterole，是在  
导入用户管理的主页时使用隐藏的输入框这种方式传递进来的，代码如下：
``` 
<input type="hidden" name="editrole" id="editrole" th:value="${editrole}"/>
<input type="hidden" name="deleterole" id="deleterole" th:value="${deleterole}"/>
```

上面这种根据权限设置链接的设计，只是在一个局部操作界面上实现，在实际应用中，可  
以通过统筹规划全局视图，在全局的角度中实现这种设计。