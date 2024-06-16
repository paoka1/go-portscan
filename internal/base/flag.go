package base

import (
	"flag"
	"fmt"
)

type flagInfo struct {
	name         string
	defaultValue string
}

var DefaultPorts = "21,22,23,53,80,3306,3389,8080,8081,8888,9000"

func Parse() {
	flag.StringVar(&RawIps, "ip", "", "ip to scan")
	flag.StringVar(&RawPorts, "p", DefaultPorts, "ports to scan")
	flag.BoolVar(&IsSYN, "syn", false, "use syn mode")
	flag.IntVar(&ThreadNum, "t", 10, "scan threads")
	flag.BoolVar(&IsShowOpen, "open", false, "only show open ports")
	flag.StringVar(&FileOutPut, "output", "", "simultaneously save output to a file")
	flag.BoolVar(&IsNoPing, "Pn", false, "no ping probe")
	flag.BoolVar(&IsTCPPing, "PT", false, "use tcp-ping mode")
	flag.IntVar(&ConTimeOut, "conTimeOut", 2, "wait time for port response in connect mode")
	flag.IntVar(&SYNTimeWait, "synTimeOut", 2, "maximum waiting time when no return packet is received in syn mode")

	flag.Usage = func() {
		flagSet := flag.CommandLine
		fmt.Printf("Usage of go-portscan(%s):\n", Version)
		order := []flagInfo{
			{"ip", ""},
			{"p", "\"" + DefaultPorts + "\""},
			{"syn", "connect mode"},
			{"t", "10"},
			{"open", "show all results"},
			{"output", "do not output to any file"},
			{"Pn", "use ping"},
			{"PT", "not use tcp-ping"},
			{"conTimeOut", "2s"},
			{"synTimeOut", "2s"},
		}

		for _, info := range order {
			f := flagSet.Lookup(info.name)
			fName, fUsage := flag.UnquoteUsage(f)
			fmt.Printf("  -%s %s\n", f.Name, fName)
			if info.defaultValue == "" {
				fmt.Printf("        %s\n", fUsage)
			} else {
				fmt.Printf("        %s (default %s)\n", fUsage, info.defaultValue)
			}
		}
	}

	flag.Parse()
}
