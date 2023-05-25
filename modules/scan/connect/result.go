package connect

import (
	"bytes"
	"fmt"
	"go-portscan/internal/base"
	"go-portscan/internal/tool"
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
	var buf bytes.Buffer

	if !base.IsShowOpen && (!base.IsNoPing || base.IsTCPPing) {
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
		filtered, _ := base.ResultFiltered.Load(key)
		if filtered != nil {
			buf.WriteString(fmt.Sprintf("Filtered ports: %v\n", filtered))
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
