## go-portscan

端口扫描器，支持多线程，支持全连接扫描（connect），支持半开放扫描（syn）

### Usage

参数：

```shell
  -ip string
        ip to scan
  -m string
        scan mode(connect or syn) (default "connect")
  -p string
        ports to scan (default "21,22,23,80,3306,8080")
  -t int
        scan threads (default 100)
```

### Examples

```shell
./go_portscan -ip 192.168.110.1 -p 80
./go_portscan -ip 192.168.110.1-10 -p 80-85,8080
./go_portscan -ip 192.168.110.1/24 -p 80-85,8080 -t 1000
./go_portscan -ip 119.45.241.1/24 -m syn -p 80,8080
```

### Todo

- [x] 全连接扫描（connect）
- [x] 半开放扫描（syn）

### Note

1. 半开放扫描需要管理员或 root 权限
2. 全连接扫描的结果中把端口区分为 Open 和 Filtered，半开放则为 Open、Filtered 和 Closed
3. 扫描器中 syn 扫描模式有时不稳定，可能会出现结果的偏差
4. 如运行 Release 中的二进制文件发生错误，请尝试安装依赖重新编译二进制文件

### Thanks to

[netxfly](https://github.com/netxfly)、[XinRoom](https://github.com/XinRoom)、[Kevin Darlington](https://github.com/kdar)