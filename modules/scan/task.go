package scan

import (
	"fmt"
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"go-portscan/modules/scan/ping"
	"go-portscan/modules/scan/syn"
	"log"
	"net"
	"sync"
	"time"
)

var ss *syn.Scan

// GenerateTask 生成扫描任务
func GenerateTask() ([]map[string]uint16, int) {
	tasks := make([]map[string]uint16, 0)

	if base.IsSYN {
		ss = syn.ScanSyn(string(base.Ips[0]))
		go ss.ListenPackage()
		ss.GetGatewayMac()
	}

	if base.IsNoPing && !base.IsTCPPing {
		for _, ip := range base.Ips {
			for _, port := range base.Ports {
				ipPort := map[string]uint16{ip.String(): port}
				tasks = append(tasks, ipPort)
			}
		}
	} else {
		var wg sync.WaitGroup
		scanBatch := len(base.Ips) / base.ThreadNum

		for i := 0; i < scanBatch; i++ {
			wg.Add(base.ThreadNum)
			curTasks := base.Ips[base.ThreadNum*i : base.ThreadNum*(i+1)]
			tasks = append(tasks, RunGenerateTask(curTasks, &wg)...)
		}

		if len(base.Ips)%base.ThreadNum > 0 {
			wg.Add(len(base.Ips) % base.ThreadNum)
			lastTasks := base.Ips[base.ThreadNum*scanBatch:]
			tasks = append(tasks, RunGenerateTask(lastTasks, &wg)...)
		}

		fmt.Println(fmt.Sprintf("%d hosts alive", len(base.Hosts)))
		fmt.Println("if other hosts alive, please use -Pn and don't use -PT")
	}

	return tasks, len(tasks)
}

// AssigningTasks 分配任务
func AssigningTasks(tasks []map[string]uint16) {
	var wg sync.WaitGroup
	scanBatch := len(tasks) / base.ThreadNum

	for i := 0; i < scanBatch; i++ {
		wg.Add(base.ThreadNum)
		curTasks := tasks[base.ThreadNum*i : base.ThreadNum*(i+1)]
		if base.IsSYN {
			syn.Run(curTasks, ss, &wg)
			time.Sleep(time.Second * 1)
		} else {
			connect.Run(curTasks, &wg)
		}
		wg.Wait()
	}

	if len(tasks)%base.ThreadNum > 0 {
		wg.Add(len(tasks) % base.ThreadNum)
		lastTasks := tasks[base.ThreadNum*scanBatch:]
		if base.IsSYN {
			syn.Run(lastTasks, ss, &wg)
		} else {
			connect.Run(lastTasks, &wg)
		}
		wg.Wait()
	}

	// 在 syn 模式，先等待两秒，再根据某个固定时间内的包数来判断是否退出
	if base.IsSYN {
		if ss.ARPTimeOut {
			log.Print("warning: timeout getting ARP reply")
		}
		time.Sleep(time.Second * 2)
		go ss.PC.RecNum()
		syn.AutoCancel(ss)
	}
}

func RunGenerateTask(curTasks []net.IP, wg *sync.WaitGroup) []map[string]uint16 {
	tasks := make([]map[string]uint16, 0)
	var lock sync.Mutex

	for _, curTask := range curTasks {
		go func(curTask net.IP) {
			if ping.IsHostLive(curTask.String(), base.IsTCPPing, !base.IsNoPing, time.Duration(base.ConTimeOut)*time.Second) {
				lock.Lock()
				base.Hosts = append(base.Hosts, curTask)
				lock.Unlock()
				for _, port := range base.Ports {
					ipPort := map[string]uint16{curTask.String(): port}
					lock.Lock()
					tasks = append(tasks, ipPort)
					lock.Unlock()
				}
			}
			wg.Done()
		}(curTask)
	}
	wg.Wait()

	return tasks
}
