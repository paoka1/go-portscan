package connect

import "sync"

// Run 执行任务
func Run(tasks []map[string]uint16, wg *sync.WaitGroup) {
	for _, task := range tasks {
		for ip, port := range task {
			go func(ip string, port uint16) {
				_ = SaveResult(Connect(ip, port))
				wg.Done()
			}(ip, port)
		}
	}
}
