package scan

import (
	"go-portscan/internal/base"
	"go-portscan/modules/scan/connect"
	"go-portscan/modules/scan/syn"
	"math/rand"
)

func StartTask() {
	tasks, _ := GenerateTask()
	rand.Shuffle(len(tasks), func(i, j int) {
		tasks[i], tasks[j] = tasks[j], tasks[i]
	})
	AssigningTasks(tasks)
}

func PrintResult() {
	if base.IsSYN {
		syn.PrintResult()
	} else {
		connect.PrintResult()
	}
}
