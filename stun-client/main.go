package main

import (
	"flag"
	"fmt"
	"github.com/ctulek/stun"
	"log"
)

var host = flag.String("h", "stun.l.google.com", "STUN Server address")
var port = flag.Int("p", 19302, "STUN Server port")
var software = flag.String("software", "Go Client", "Client Name to send to server")

func main() {
	flag.Parse()
	var opts stun.ClientOpts
	opts.Software = *software

	addr, err := stun.Call(*host, *port, opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v %d\n", addr.IP, addr.Port)
}
