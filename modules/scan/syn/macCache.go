package syn

import (
	"net"
	"sync"
)

type MacCacheMap struct {
	lock     sync.RWMutex
	MacCache map[string]net.HardwareAddr
}

// GetMacByIp 获取缓存的 Mac 地址
func (m *MacCacheMap) GetMacByIp(ip string) net.HardwareAddr {
	m.lock.Lock()
	if mac, ok := m.MacCache[ip]; ok {
		m.lock.Unlock()
		return mac
	}
	m.lock.Unlock()
	return nil
}

// AddMacIp 添加缓存 Mac 地址
func (m *MacCacheMap) AddMacIp(ip string, mac net.HardwareAddr) {
	m.lock.Lock()
	m.MacCache[ip] = mac
	m.lock.Unlock()
}
