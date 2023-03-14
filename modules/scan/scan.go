package scan

import (
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"go-portscan/modules/scan/syn"
)

func StartTask() {
	tasks, _ := GenerateTask()
	AssigningTasks(tasks)
}

func PrintResult() {
	if base.Mode == "connect" {
		connect.PrintResult()
	} else {
		syn.PrintResult()
	}
}
