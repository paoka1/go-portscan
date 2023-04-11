package syn

import (
	"go-portscan/internal/base"
	"net"
	"sync"
)

type IpPort struct {
	lock    sync.RWMutex
	IpPosts []map[string][]uint16
}

var (
	Ipc IpPort
)

func init() {
	Ipc.IpPosts = make([]map[string][]uint16, 0)
}

// IsIpExist 判断 ip 是否为我们要检测的 ip
func IsIpExist(ip string) bool {
	for _, i := range base.Ips {
		if i.Equal(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

// HasPort 判断 port 是否为记录
func (i *IpPort) HasPort(ip string, port uint16) bool {
	i.lock.Lock()
	defer i.lock.Unlock()

	for _, v := range i.IpPosts {
		if vv, ok := v[ip]; ok {
			for _, p := range vv {
				if port == p {
					return true
				}
			}
			return false
		}
	}
	return false
}

// RecordPort 记录 port
func (i *IpPort) RecordPort(ip string, port uint16) {
	i.lock.Lock()
	defer i.lock.Unlock()

	for _, v := range i.IpPosts {
		if vv, ok := v[ip]; ok {
			v[ip] = append(vv, port)
			return
		}
	}
	i.IpPosts = append(i.IpPosts, map[string][]uint16{ip: {port}})
}
