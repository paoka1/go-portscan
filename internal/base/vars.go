package base

import (
	"net"
	"sync"
)

var (
	RawIps   string // 来自命令行的 ip 参数
	RawPorts string // 来自命令行的 port 参数

	Ips   []net.IP // 处理后的 ip
	Ports []uint16 // 处理后的 port
	Hosts []net.IP // 存活的主机

	ThreadNum   int    // 线程数
	IsSYN       bool   // 是否为 syn 模式
	IsShowOpen  bool   // 是否只输出端口开启的 ip
	IsNoPing    bool   // 是否禁用 ping
	IsTCPPing   bool   // 是否启用 tcp ping 检测主机存活
	FileOutPut  string // 输出到某个文件
	ConTimeOut  int    // connect 模式中端口响应的等待时间
	SYNTimeWait int    // syn 模式中未收到返回包时最大等待的时长

	ResultOpen     *sync.Map // Port Open
	ResultClosed   *sync.Map // Port Closed
	ResultFiltered *sync.Map // Port Filtered
)

func init() {
	ResultOpen = &sync.Map{}
	ResultClosed = &sync.Map{}
	ResultFiltered = &sync.Map{}
}
