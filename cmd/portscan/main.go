package portscan

import (
	"go-portscan/modules/scan"
	"go-portscan/modules/util"
	"runtime"
)

func Main() {
	util.SetParam()
	defer util.TimeCost()()
	scan.StartTask()
	scan.PrintResult()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
