package syn

import (
	"bytes"
	"fmt"
	"go-portscan/internal/base"
	"go-portscan/internal/tool"
	"strings"
)

// SaveResult 保存扫描结果
func SaveResult(ip string, port uint16, portType string) {
	if portType == "open" {
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
	}

	if portType == "closed" {
		v, ok := base.ResultClosed.Load(ip)
		if ok {
			ports, ok1 := v.([]uint16)
			if ok1 {
				ports = append(ports, port)
				base.ResultClosed.Store(ip, ports)
			}
		} else {
			ports := make([]uint16, 0)
			ports = append(ports, port)
			base.ResultClosed.Store(ip, ports)
		}
	}
}

// GetFilteredPort 获取 Filtered Port
func GetFilteredPort(ip interface{}) {
	var isFind = false

	value1, _ := base.ResultOpen.Load(ip)
	value2, _ := base.ResultClosed.Load(ip)

	closed, _ := value2.([]uint16)
	open, _ := value1.([]uint16)

	for _, port := range base.Ports {
		for _, openPort := range open {
			if port == openPort {
				isFind = true
				break
			}
		}

		if !isFind {
			for _, closedPort := range closed {
				if port == closedPort {
					isFind = true
					break
				}
			}
		}

		if isFind {
			isFind = false
			continue
		}

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
	}
}

// PrintResult 打印结果
func PrintResult() {
	var buf bytes.Buffer

	if !base.IsShowOpen && (!base.IsNoPing || base.IsTCPPing) {
		base.ResultOpen.Range(func(key, value interface{}) bool {
			GetFilteredPort(key)
			return true
		})

		for _, ip := range base.Hosts {
			buf.WriteString(fmt.Sprintf("Target ip:%v\n", ip))
			opened, _ := base.ResultOpen.Load(ip.String())
			if opened != nil {
				buf.WriteString(fmt.Sprintf("Open ports: %v\n", opened))
			}
			filtered, _ := base.ResultFiltered.Load(ip.String())
			if filtered != nil {
				buf.WriteString(fmt.Sprintf("Filtered ports: %v\n", filtered))
			}
			closed, _ := base.ResultClosed.Load(ip.String())
			if closed != nil {
				buf.WriteString(fmt.Sprintf("Closed ports: %v\n", closed))
			}
			buf.WriteString(fmt.Sprintf(strings.Repeat("-", 60) + "\n"))
		}

		if buf.Len() != 0 {
			fmt.Println(strings.TrimRight(buf.String(), "\n"))
		}
		tool.SaveToFile(base.FileOutPut, buf)
		return
	}

	base.ResultOpen.Range(func(key, value interface{}) bool {
		buf.WriteString(fmt.Sprintf("Target ip:%v\n", key))
		if value != nil {
			buf.WriteString(fmt.Sprintf("Open ports: %v\n", value))
		}
		GetFilteredPort(key)
		filtered, _ := base.ResultFiltered.Load(key)
		if filtered != nil {
			buf.WriteString(fmt.Sprintf("Filtered ports: %v\n", filtered))
		}
		closed, _ := base.ResultClosed.Load(key)
		if closed != nil {
			buf.WriteString(fmt.Sprintf("Closed ports: %v\n", closed))
		}
		buf.WriteString(fmt.Sprintf(strings.Repeat("-", 60) + "\n"))
		return true
	})

	if buf.Len() != 0 {
		fmt.Println(strings.TrimRight(buf.String(), "\n"))
	}
	tool.SaveToFile(base.FileOutPut, buf)
	return
}
