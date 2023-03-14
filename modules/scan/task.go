package scan

import (
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"go-portscan/modules/scan/syn"
	"log"
	"net"
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
	scanBatch := len(tasks) / base.ThreadNum

	for i := 0; i < scanBatch; i++ {
		curTask := tasks[base.ThreadNum*i : base.ThreadNum*(i+1)]
		RunTask(curTask)
	}

	if len(tasks)%base.ThreadNum > 0 {
		lastTasks := tasks[base.ThreadNum*scanBatch:]
		RunTask(lastTasks)
	}
}

// RunTask 执行任务
func RunTask(tasks []map[string]uint16) {
	var wg sync.WaitGroup
	wg.Add(len(tasks))

	// 每次创建 len(tasks) 个 goroutine，每个 goroutine 只处理一个 ip:port 对的检测
	if base.Mode == "connect" {
		// connect
		for _, task := range tasks {
			for ip, port := range task {
				go func(ip string, port uint16) {
					_ = connect.SaveResult(connect.Connect(ip, port))
					wg.Done()
				}(ip, port)
			}
		}
	} else {
		// syn
		ss := syn.ScanSyn(string(base.Ips[0]))
		go ss.ListenPackage()
		ss.GetGatewayMac()
		for _, task := range tasks {
			for ip, port := range task {
				go func(ip string, port uint16) {
					err := ss.SendPackage(net.ParseIP(ip), port)
					if err != nil {
						log.Print(err)
					}
					wg.Done()
				}(ip, port)
			}
		}
		time.Sleep(time.Second * 2)
	}
	wg.Wait()
}
