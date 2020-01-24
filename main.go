package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/c-sto/goWMIExec/pkg/wmiexec"
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
	}

	if target == "" || (password == "" && hash == "") {
		flag.Usage()
		os.Exit(1)
	}

	if !strings.Contains(target, ":") {
		fmt.Printf("Bad target specified, requires port (usually 135). expected: 127.0.0.1:135, got %s", target)
		os.Exit(1)
	}

	err := wmiexec.WMIExec(target, username, password, hash, domain, command, clientHost, nil)
	if err != nil {
		panic(err)
	}

}
