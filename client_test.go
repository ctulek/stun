package stun

import (
	"net"
	"testing"
)

func TestSendBindingRequest(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp4", "stun.l.google.com:19302")
	if err != nil {
		t.Error(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Error(err)
	}
	response, err := SendBindingRequest(conn, addr)
	if err != nil {
		t.Error(err)
	}
	if response.Header.IsValid() == false {
		t.Error(response)
	}
}
