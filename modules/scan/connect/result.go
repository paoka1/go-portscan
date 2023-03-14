package connect

import (
	"fmt"
	"go-portscan/internal/base"
	"strings"
)

// SaveResult 保存扫描结果
func SaveResult(ip string, port uint16, err error) error {
	if err != nil {
		v, ok := base.ResultFiltered.Load(ip)
		if ok {
			ports, ok1 := v.([]uint16)
			if ok1 {
				ports = append(ports, port)
				base.ResultFiltered.Store(ip, ports)
			}
		} else {
			ports := make([]uint16, 0)
			ports = append(ports, port)
			base.ResultFiltered.Store(ip, ports)
		}
		return err
	}

	v, ok := base.ResultOpen.Load(ip)
	if ok {
		ports, ok1 := v.([]uint16)
		if ok1 {
			ports = append(ports, port)
			base.ResultOpen.Store(ip, ports)
		}
	} else {
		ports := make([]uint16, 0)
		ports = append(ports, port)
		base.ResultOpen.Store(ip, ports)
	}
	return err
}

// PrintResult 打印结果
func PrintResult() {
	base.ResultOpen.Range(func(key, value interface{}) bool {
		fmt.Printf("Target ip:%v\n", key)
		if value != nil {
			fmt.Printf("Open ports: %v\n", value)
		}
		filtered, _ := base.ResultFiltered.Load(key)
		if filtered != nil {
			fmt.Printf("Filtered ports: %v\n", filtered)
		}
		fmt.Println(strings.Repeat("-", 60))
		return true
	})
}
