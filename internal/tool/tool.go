package tool

import (
	"bytes"
	"log"
	"os"
	"strings"
)

func SaveToFile(fileName string, content bytes.Buffer) {
	if fileName == "" {
		return
	}

	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Fatalln("fail to open file, ", err)
	}
	defer func() {
		err = f.Close()
		if err != nil {
			log.Fatalln("fail to close file, ", err)
		}
	}()

	if content.Len() != 0 {
		_, err = f.WriteString(strings.TrimRight(content.String(), "\n"))
		if err != nil {
			log.Fatalln("fail to write file, ", err)
		}
	}
	return
}
