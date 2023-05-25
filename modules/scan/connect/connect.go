package connect

import (
	"fmt"
	"go-portscan/internal/base"
	"net"
	"time"
)

// Connect connect scan
func Connect(ip string, port uint16) (string, uint16, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), time.Duration(base.ConTimeOut)*time.Second)

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	return ip, port, err
}
