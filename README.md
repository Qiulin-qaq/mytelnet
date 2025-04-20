# 自定义TCP/IP协议栈实现

这个项目实现了一个自定义的TCP/IP协议栈，可以进行基本的HTTP通信。它使用libpcap直接在数据链路层操作，而不是使用标准的socket API。

## 编译指令

安装必要的依赖：

```bash
sudo apt update
sudo apt install -y g++ libpcap-dev
```

编译项目：

```bash
g++ -std=c++17 -o mytelnet *.cpp -lpcap
```

## 运行指令

需要root权限运行（因为需要访问网络接口）：

```bash
sudo ./mytelnet <目标IP地址> <端口>
```

例如：

```bash
sudo ./mytelnet 155.138.142.54 80
```

## 抓包分析

使用tcpdump抓取与特定主机和端口的通信：

```bash
sudo tcpdump -i ens33 -n "host 155.138.142.54 and tcp port 80" -vv
```

将抓取的包保存到文件：

```bash
sudo tcpdump -i ens33 -w capture.pcap -n "host 155.138.142.54 and tcp port 80"
```

用Wireshark打开保存的捕获文件：

```bash
wireshark capture.pcap
```

实时抓包并直接用Wireshark分析：

```bash
sudo wireshark -i ens33 -k -f "host 155.138.142.54 and tcp port 80"
```

## iptables规则

### 阻止RST包

如果本地操作系统的TCP/IP栈对它不认识的连接发送RST包，可以使用以下iptables规则阻止：

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 155.138.142.54 --dport 80 -j DROP
```


查看当前规则：

```bash
sudo iptables -L -v
```

 
