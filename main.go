package main

import (
	"flag"
	"os"
	"strings"

	"github.com/c-sto/goInvokeWMIExec/pkg/wmiexec"
)

func main() {

	var command, target, username, password, hash, domain, clientHost string
	flag.StringVar(&target, "target", "", "Target. Include port (:135)")
	flag.StringVar(&username, "username", "", "Username to auth as")
	flag.StringVar(&password, "password", "", "password")
	flag.StringVar(&hash, "hash", "", "hash")
	flag.StringVar(&command, "command", "", "command")
	flag.StringVar(&clientHost, "clientname", "", "")
	flag.Parse()

	if clientHost == "" {
		var err error
		clientHost, err = os.Hostname()
		if err != nil {
			panic(err)
		}
		clientHost = strings.ToUpper(clientHost)
		if len(clientHost) > 16 {
			clientHost = clientHost[:15]
		}
	}

	wmiexec.WMIExec(target, username, password, hash, domain, command, clientHost)

}
