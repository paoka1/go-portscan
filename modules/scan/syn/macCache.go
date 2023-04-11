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
	defer m.lock.Unlock()

	if mac, ok := m.MacCache[ip]; ok {
		return mac
	}
	return nil
}

// AddMacIp 添加缓存 Mac 地址
func (m *MacCacheMap) AddMacIp(ip string, mac net.HardwareAddr) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.MacCache[ip] = mac
}
