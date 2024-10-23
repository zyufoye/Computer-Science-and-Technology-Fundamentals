## 0x00 代码执行漏洞概述
当应用调用一些字符串转代码的函数时，没有考虑用户能否控制这个字符串，就会造成代码注入漏洞（代码执行漏洞）。

## 0x01 常见的代码执行函数
php： eval(),assert(),preg_replace()；
python：eval()；
java：Java没有类似于前面二者的函数，但是Java有反射机制，并且有基于反射机制的表达式引擎，如：OGNL、SpEL、MVEL等；

## 0x02 代码执行漏洞示例
```php
<?php
$a="phpinfo();";
eval($a);
?>
```
上述代码中，a是一个变量，里面保存了一个字符串，按理来说字符串是不能运行的，但是传到eval函数中，就能正常执行phpinfo，eval函数的作用就是把字符串当成代码来执行。
### 1.动态代码执行漏洞
动态代码执行漏洞，在程序开发过程中，需要动态调用函数，如果参数可控的情况下，会造成代码执行漏洞。
```php
<?php
function m_print(){
    echo '这是一个页面';
}
$_GET['a']($_GET['b']);
?>
```
上面代码中最后一行，a（b），a表示函数名称，b在括号里，就表示接收的值，如果我们给a传入assert，给b传入要执行的payload，就会触发代码执行漏洞。
查看php信息：
assert可以执行php里面的一些函数比如 phpinfo() ，payload如下：
```url
https://www.test.com/test.php?a=assert&b=phpinfo();
```

### 2.eval代码执行漏洞
```php
<?php
$data = isset($_GET['data'])?$_GET['data']:'这是一个 eval 漏洞页面';
@eval($ret = $data);
echo $ret;
?>
```
eval — 把字符串作为 PHP 代码执行，@符号是用于抑制错误输出的操作符。

### 3.正则代码执行漏洞
```php
<?php
$data = $_GET['data'];
preg_replace('/<data>(.*)<\/data>/e','$ret = "\\1";',$data);
?>
<form>
<label>请输入你的数据</label>
<input type='text' name='data'/>
<input type='submit' value='提交'/>
</form>
输入：
<data>{${phpinfo()}}</data>

```
preg_replace 使用了 /e 模式，导致可以代码执行。  
/e 修饰符表示执行（evaluate），也就是匹配到的内容会被当成PHP代码来执行。  
```txt
/<data>(.*)<\/data>/ 匹配的是 <data> 标签之间的任何内容。(.*) 用于捕获 <data> 和 </data> 之间的字符串，并将其存储在一个捕获组中，

/e 会将正则表达式的匹配结果作为PHP代码来执行，这就是此代码的漏洞所在。因为 preg_replace 中使用了 /e 修饰符，任何在 <data> 标签中的内容都会被PHP执行，导致代码注入风险。
```

### 4.代码执行漏洞的攻击方法
代码执行漏洞因为可以注入执行脚本代码，所以利用手段很多，常见的就是获取敏感信息，写入Web后门等。
通过 PHP 将一个简单的 WebShell 写入到名为 shell.php 的文件中：
```php
fputs(fopen("shell.php","a"), "<?php phpinfo();?>");
```
fopen 函数用于打开一个文件，参数 "shell.php" 是文件名，表示要打开或创建的文件是 shell.php。
第二个参数 "a" 表示文件的追加模式（append mode）。这意味着：
- 如果 shell.php 已经存在，新的内容将被追加到文件的末尾；
- 如果文件不存在，fopen 会创建一个新文件并打开它；  

fputs 是用于写入字符串到文件中的函数。它接收两个参数：
- 第一个参数是一个文件句柄（由 fopen 返回的资源），表示将内容写入哪个文件；
- 第二个参数是需要写入的字符串；  

### 5.代码执行漏洞防御方法
1. 使用json保存数组，读取时不使用eval；
2. 对于必须使用eval的地方，利用黑白名单严格处理用户输入数据；
3. 字符串使用单引号包裹可控代码，插入前转义处理（addslashes、htmlspecialchars、htmlentities、mysql_real_escape_string）；
4. 使用preg_replace正则表达式时，不使用 \e 修饰符，使用preg_replace_callback()替换preg_replace_callback()，它通过回调函数处理匹配到的结果，而不是直接执行代码，从而提高安全性；
