package stun

import (
	"bytes"
	"net"
	"testing"
)

var b_BINDING_RESPONSE_WITH_ALTERNATE_SERVER = []byte{
	0x01, 0x01, 0x00, 0x0C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x80, 0x23, 0x00, 0x08, // Alternate Server
	0x00, 0x01, 0x04, 0x00,
	0xC0, 0xA8, 0x00, 0x01, // 192.168.0.1
}

func TestUnPackAlternateServer(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_BINDING_RESPONSE_WITH_ALTERNATE_SERVER)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Attribute count is wrong")
	}
	alternate := m.Attributes[0].(*AlternateServer)
	if alternate.Family != 0x01 {
		t.Error("Wrong Family")
	}
	if alternate.Port != 1024 {
		t.Error("Wrong Port", alternate.Port)
	}
	if alternate.IP.String() != "192.168.0.1" {
		t.Error("Wrong IP", alternate.IP)
	}
}

func TestPackWithAlternateServer(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)

	alternate := new(AlternateServer)
	alternate.Family = 0x01
	alternate.Port = 1024
	alternate.IP = net.ParseIP("192.168.0.1")
	t.Log(alternate.IP)
	m.AddAttribute(alternate)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 32 {
		t.Error("Buffer length is wrong")
	}
	err := m.Pack(b)
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal(b, b_BINDING_RESPONSE_WITH_ALTERNATE_SERVER) == false {
		t.Log(b)
		t.Log(b_BINDING_RESPONSE_WITH_ALTERNATE_SERVER)
		t.Error("Pack failed")
	}
}
