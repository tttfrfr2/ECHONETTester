package main

import (
	"fmt"
	"net"
	"time"

	"github.com/DaikiYamakawa/VulnApplianceScanner/echonetlite"
	"github.com/DaikiYamakawa/VulnApplianceScanner/util"
)

var auditor echonetlite.Auditor
var echonetConf util.EchonetLiteConf

func main() {
	t := time.Now()
	echonetlite.TimeStr = fmt.Sprint(t.Year()) + "-" + fmt.Sprint(int(t.Month())) + "-" + fmt.Sprint(t.Day()) + "-" + fmt.Sprint(t.Minute()) + "-" + fmt.Sprint(t.Second())

	var config *util.Config
	config = util.ReadConfig("config.tml")
	if config == nil {
		return
	}
	echonetConf = util.DistributeConf(*config)
	fmt.Println("---Tool Start---")

	var echonetTargets []net.IP
	for _, ip := range echonetConf.IP {
		echonetTargets = append(echonetTargets, net.ParseIP(ip))
	}
	err := auditor.NewAuditor(echonetTargets)
	if err != nil {
		fmt.Printf("ECHONET Lite testing ERROR: %+v\n", err)
	}

	if len(auditor.DistNodes) < 1 {
		fmt.Printf("There are no ECHONET Lite node\nEXIT\n")
		return
	}
	auditor.RunEchonetPrompt()

}
