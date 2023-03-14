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
	Ports []uint16 // 处理后的 port

	ThreadNum int // 线程数

	ResultOpen     *sync.Map // Port Open
	ResultClosed   *sync.Map // Port Closed
	ResultFiltered *sync.Map // Port Filtered
)

func init() {
	ResultOpen = &sync.Map{}
	ResultClosed = &sync.Map{}
	ResultFiltered = &sync.Map{}
}
