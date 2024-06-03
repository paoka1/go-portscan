package util

import (
	"flag"
	"github.com/malfunkt/iprange"
	"go-portscan/internal/base"
	"log"
	"strconv"
	"strings"
	"time"
)

// SetParam 处理 ip、port 参数
func SetParam() {
	base.Parse()
	SetIpList()
	SetPortList()
}

// TimeCost 计算扫描所消耗时间
func TimeCost() func() {
	start := time.Now()
	return func() {
		cost := time.Since(start)
		log.Printf("scan down, %d IP addresses in %v\n", len(base.Ips), cost)
	}
}

// SetIpList 分割解析 ip 地址，赋值给全局变量 Ips
func SetIpList() {
	if base.RawIps == "" {
		flag.PrintDefaults()
		log.Fatalf("missing ip parameter")
	}

	if strings.Contains(base.RawIps, ",") {
		log.Fatalf("multiple different ip parameters are not allowed")
	}

	if strings.Contains(base.RawIps, ", ") {
		log.Fatalf("multiple different ip parameters are not allowed")
	}

	addressList, err := iprange.ParseList(base.RawIps)
	if err != nil {
		log.Fatalf(err.Error())
	}

	base.Ips = addressList.Expand()
}

// SetPortList 分割解析 port，赋值给全局变量 Ports
func SetPortList() {
	ranges := strings.Split(base.RawPorts, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				log.Fatalf("invalid port selection segment: %s", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				log.Fatalf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Fatalf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				log.Fatalf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				base.Ports = append(base.Ports, uint16(i))
			}
		} else {
			if port, err := strconv.Atoi(r); err != nil {
				log.Fatalf("invalid port number: '%s'", r)
			} else {
				base.Ports = append(base.Ports, uint16(port))
			}
		}
	}
}
