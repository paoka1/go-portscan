package syn

import (
	"log"
	"net"
	"sync"
)

// Run 执行任务
func Run(tasks []map[string]uint16, ss *Scan, wg *sync.WaitGroup) {
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
}
