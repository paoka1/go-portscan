package base

import (
	"flag"
)

func Parse() {
	flag.StringVar(&RawIps, "ip", "", "ip to scan")
	flag.StringVar(&RawPorts, "p", "21,22,23,80,3306,8080", "ports to scan")
	flag.IntVar(&ThreadNum, "t", 100, "scan threads")
	flag.StringVar(&Mode, "m", "connect", "scan mode(connect or syn)")
	flag.Parse()
}
