package scan

func StartTask() {
	tasks, _ := GenerateTask()
	AssigningTasks(tasks)
}
