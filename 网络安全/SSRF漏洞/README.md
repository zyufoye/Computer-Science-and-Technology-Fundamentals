## 0x00 SSRF漏洞概述
SSRF（服务器端请求伪造，Server-Side Request Forgery）是一种攻击手段，攻击者通过伪造请求，诱使服务器向内部或外部资源发送请求。由于服务器的权限通常比用户广泛，SSRF漏洞可能允许攻击者获取服务器内部的敏感信息、访问未公开的服务，甚至通过进一步利用服务器攻击其他系统。

SSRF 由攻击者构造请求，由服务端发起请求，其攻击目标一般是外网无法访问的内部系统。

## 0x01 SSRF攻击的原理
SSRF 攻击的本质是通过控制服务器发出的请求来获取对其资源的访问权限，通常发生在服务器需要接收并根据用户的输入，然后再发送请求的情况下。
例如，服务器可能会根据用户提供的URL从外部资源获取数据。如果服务器没有正确验证或限制该URL的范围，攻击者就可以利用这一点，操纵请求，使其访问攻击者指定的任意资源。

SSRF的形成大多是由于服务端提供了从其他服务器应用获取数据的功能，但是没有对目标地址做任何过滤和限制。SSRF利用存在漏洞的Web应用作为代理，去攻击远程和本地的服务器。

## 0x03 SSRF主要攻击方式
1. 对外网、服务器所在内网等进行端口扫描，内网信息嗅探；
2. 攻击运行在本地或内网的应用程序；
3. 对内网 Web 应用进行指纹识别，识别企业内部的资产信息；
4. 利用 file 协议读取本地文件；
5. 攻击内外网的 Web 应用，主要是使用 HTTP GET 请求就可以实现的攻击(比如 struts2、SQli 等)；

## 0x04 SSRF漏洞代码分析
url 没有任何过滤传入，php 中的 curl 是 通过 http 请求访问远程页面。
```php
if (isset($_GET['url']) && $_GET['url'] != null) {
    $url = $_GET['url'];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // 关闭SSL证书验证
    $RES = curl_exec($ch);  // 执行cURL请求
    curl_close($ch);
    echo $RES;
}

```
代码没有对用户输入的 url 进行任何过滤或验证。这意味着攻击者可以传入任意 url，导致服务端发起对恶意外部资源 或 内网资源的请求。

## 0x04 SSRF漏洞攻击 
SSRF 支持多种协议所以漏洞利用的方法很多。  

### 1.http:// 协议
能进行内网端口探测：可以通过返回的时间长短判断端口的开放。一般访问速度较快则开启了对应端口，访问速度很慢则对应端口没有开启。  
然后根据banner信息判断内网的敏感信息。

### 2.file:// 协议读取文件 
http://192.168.0.103/06/vul/ssrf/ssrf_curl.php?url=file:///etc/passwd

### 3.dict:// 协议内网扫描
能进行内网端口的探测-可以探测到具体的版本号等等信息。
http://192.168.0.103/06/vul/ssrf/ssrf_curl.php?url=dict://127.0.0.1:3306

### 3.gopher:// 协议
能进行内网端口的探测-可以发送 get 或者来攻击内网的 redis 等服务。
http://192.168.0.103/06/vul/ssrf/ssrf_curl.php?url=gopher://127.0.0.1:3306


## 0x05 SSRF支持的协议
```txt
1.文件传输协议（21号端口）
ftp://
ssrf.php?url=ftp://evil.com:12345/TEST

2.file是一种 URI（统一资源标识符）协议，用于访问本地文件系统中的资源。
file://
ssrf.php?url=file:///etc/password

3.DICT 是一种基于 TCP 的应用层协议，全称为 Dictionary Server Protocol，用于从远程字典服务器查询词汇定义和相关信息。
它的应用场景通常是在在线字典查询工具和应用程序中。
dict://
dict://<user-auth>@<host>:<port>/d:<word>
ssrf.php?url=dict://attacker:11111/

4.SFTP是一种通过 SSH 协议提供文件访问、传输和管理的网络协议。
SFTP://
ssrf.php?url=sftp://example.com:11111/

5.TFTP是简易文件传输协议，用于在客户端和服务器之间传输文件的简单协议。
与 FTP 或 SFTP 不同，TFTP 使用 UDP  进行传输，通常在 69 端口上运行。
TFTP://
ssrf.php?url=tftp://example.com:12346/TESTUDPPACKET

6.LDAP 是轻量级目录访问协议，是一种应用层协议，用于访问和维护分布式目录信息服务。
LDAP://
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit

7. gopher 是一种早期的互联网协议，设计用于在分层目录结构中分发、搜索和检索文档。
使用TCP协议，默认端口号70 。
Gopher://
ssrf.php?url=gopher://127.0.0.1:3306

```

## 0x06 SSRF漏洞防御方案
1. 禁止页面跳转；
2. 过滤返回信息，验证远程服务器对该请求的响应是否符合标准；
3. 禁用不需要的协议，例如仅允许http或https等，禁用ftp、file、gopher等协议；
4. 设置URL白名单和内网IP，限制请求端口；
5. 统一错误显示信息，避免攻击者根据错误回显判断远程服务器状态；