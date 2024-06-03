package ping

/*
	此处 ping 的实现参考了 https://github.com/XinRoom/go-portScan/blob/main/core/host/ping.go
	该项目使用 Apache-2.0 开源协议，故此说明
*/

import (
	"github.com/go-ping/ping"
	"time"
)

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

var CanIcmp bool

var TcpPingPorts = []uint16{80, 22, 445, 23, 443, 81, 161, 3389, 8080, 8081}

// 判断是否支持发送 icmp 包
func init() {
	if DoIcmp("127.0.0.1") {
		CanIcmp = true
	}
}

// IsHostLive 判断 ip 是否存活
func IsHostLive(ip string, tcpPing bool, ping bool, tcpTimeout time.Duration) (ok bool) {
	ok = false

	if ping {
		if CanIcmp {
			ok = DoIcmp(ip)
		} else {
			ok = DoPing(ip)
		}
	}

	if !ok && tcpPing {
		ok = TcpPing(ip, TcpPingPorts, tcpTimeout)
	}

	return ok
}

// DoPing Ping 命令模式
func DoPing(host string) bool {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		_ = cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
			return true
		}

	case "windows":
		cmd := exec.Command("ping", "-n", "1", "-w", "500", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		_ = cmd.Run()
		if strings.Contains(out.String(), "TTL=") {
			return true
		}

	case "darwin":
		cmd := exec.Command("ping", "-c", "1", "-t", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		_ = cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
			return true
		}
	}

	return false
}

// DoIcmp 直接发 ICMP 包
func DoIcmp(host string) bool {
	newPinger, err := ping.NewPinger(host)
	if err != nil {
		return false
	}
	newPinger.SetPrivileged(true)
	newPinger.Count = 1
	newPinger.Timeout = 800 * time.Millisecond
	if newPinger.Run() != nil { // Blocks until finished. return err
		return false
	}
	if stats := newPinger.Statistics(); stats.PacketsRecv > 0 {
		return true
	}
	return false
}

// TcpPing 指定默认常见端口进行存活探测
func TcpPing(host string, ports []uint16, timeout time.Duration) (ok bool) {
	var wg sync.WaitGroup
	for _, port := range ports {
		time.Sleep(10 * time.Millisecond)
		wg.Add(1)
		go func(_port uint16) {
			conn, _ := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, _port), timeout)
			if conn != nil {
				_ = conn.Close()
				ok = true
			}
			wg.Done()
		}(port)
	}
	wg.Wait()
	return
}
