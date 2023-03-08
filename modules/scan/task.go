package scan

import (
	"fmt"
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"strings"
	"sync"
)

// GenerateTask 生成扫描任务
func GenerateTask() ([]map[string]int, int) {
	tasks := make([]map[string]int, 0)

	for _, ip := range base.Ips {
		for _, port := range base.Ports {
			ipPort := map[string]int{ip.String(): port}
			tasks = append(tasks, ipPort)
		}
	}

	return tasks, len(tasks)
}

// AssigningTasks 分配任务
func AssigningTasks(tasks []map[string]int) {
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
func RunTask(tasks []map[string]int) {
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	// 每次创建 len(tasks) 个 goroutine，每个 goroutine 只处理一个 ip:port 对的检测
	for _, task := range tasks {
		for ip, port := range task {
			if base.Mode == "connect" {
				go func(ip string, port int) {
					err := SaveResult(connect.Connect(ip, port))
					_ = err
					wg.Done()
				}(ip, port)
			}
		}
	}
	wg.Wait()
}

// SaveResult 保存扫描结果
func SaveResult(ip string, port int, err error) error {
	if err != nil {
		return err
	}

	v, ok := base.Result.Load(ip)
	if ok {
		ports, ok1 := v.([]int)
		if ok1 {
			ports = append(ports, port)
			base.Result.Store(ip, ports)
		}
	} else {
		ports := make([]int, 0)
		ports = append(ports, port)
		base.Result.Store(ip, ports)
	}
	return err
}

// PrintResult 打印结果
func PrintResult() {
	base.Result.Range(func(key, value interface{}) bool {
		fmt.Printf("target ip:%v\n", key)
		fmt.Printf("open ports: %v\n", value)
		fmt.Println(strings.Repeat("-", 60))
		return true
	})
}
