package base

import (
	"net"
	"sync"
)

var (
	RawIps   string // 来自命令行的 ip 参数
	RawPorts string // 来自命令行的 port 参数
	Mode     string // 来自命令行的 mode 参数

	Ips   []net.IP // 处理后的 ip
	Ports []int    // 处理后的 port

	ThreadNum int // 线程数

	Result *sync.Map // 存储结果
)

func init() {
	Result = &sync.Map{}
}
