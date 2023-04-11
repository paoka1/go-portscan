package scan

import (
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"go-portscan/modules/scan/syn"
	"sync"
	"time"
)

// GenerateTask 生成扫描任务
func GenerateTask() ([]map[string]uint16, int) {
	tasks := make([]map[string]uint16, 0)

	for _, ip := range base.Ips {
		for _, port := range base.Ports {
			ipPort := map[string]uint16{ip.String(): port}
			tasks = append(tasks, ipPort)
		}
	}

	return tasks, len(tasks)
}

// AssigningTasks 分配任务
func AssigningTasks(tasks []map[string]uint16) {
	var ss *syn.Scan
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	scanBatch := len(tasks) / base.ThreadNum

	if base.Mode == "syn" {
		ss = syn.ScanSyn(string(base.Ips[0]))
		go ss.ListenPackage()
		ss.GetGatewayMac()
	}

	for i := 0; i < scanBatch; i++ {
		curTask := tasks[base.ThreadNum*i : base.ThreadNum*(i+1)]
		if base.Mode == "connect" {
			connect.Run(curTask, &wg)
		} else {
			syn.Run(curTask, ss, &wg)
		}
	}

	if len(tasks)%base.ThreadNum > 0 {
		lastTasks := tasks[base.ThreadNum*scanBatch:]
		if base.Mode == "connect" {
			connect.Run(lastTasks, &wg)
		} else {
			syn.Run(lastTasks, ss, &wg)
		}
	}
	wg.Wait()

	// 在 syn 模式，先等待两秒，再根据每秒的包数来判断是否退出
	if base.Mode == "syn" {
		time.Sleep(time.Second * 2)
		go ss.PC.RecNum()
		syn.AutoCancel(ss)
	}
}
