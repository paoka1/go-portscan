package connect

import (
	"fmt"
	"net"
	"time"
)

// Connect connect scan
func Connect(ip string, port uint16) (string, uint16, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), 2*time.Second)

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	return ip, port, err
}
