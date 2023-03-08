## go-portscan

端口扫描器，支持多线程，支持全连接（connect）扫描

### Usage

参数：

```shell
  -ip string
        ip to scan
  -m string
        scan mode (default "connect")
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
```

### Todo

- [x] 全连接扫描（connect）
- [ ] 半开放扫描（syn）

### Thanks to

[netxfly](https://github.com/netxfly)、[XinRoom](https://github.com/XinRoom)、[Kevin Darlington](https://github.com/kdar)