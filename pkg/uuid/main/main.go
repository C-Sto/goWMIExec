package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/C-Sto/goWMIExec/pkg/uuid"
)

func main() {
	f := flag.String("test", "hexhexhex", "hex")
	flag.Parse()
	s := strings.ReplaceAll(*f, ",", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(uuid.FromBytes(b))
}
