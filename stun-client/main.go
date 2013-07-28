package main

import (
	"flag"
	"github.com/ctulek/stun"
)

var host = flag.String("h", "stun.l.google.com", "STUN Server address")
var port = flag.Int("p", 19302, "STUN Server port")

func main() {
	flag.Parse()
    stun.Call(*host, *port)
}
