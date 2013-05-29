package stun

import (
	"bytes"
	"net"
	"testing"
)

var b_MESSAGE_WITH_XOR_MAPPED_ATTR = []byte{
	0x01, 0x01, 0x00, 0x0C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x20, 0x00, 0x08, // XOR Mapped Address
	0x00, 0x01, 0x25, 0x12, // FAMILY, Port 1024 XOR RFC5389_COOKIE
	0xE1, 0xBA, 0xA6, 0x43, // 192.168.2.1 XOR RFC5389_COOKIE
}

func TestPackXorMappedAddress(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	xor := new(XORMappedAddress)
	xor.Family = 0x01
	xor.Port = 1024
	xor.IP = net.ParseIP("192.168.2.1")
	m.AddAttribute(xor)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 32 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_XOR_MAPPED_ATTR) {
		t.Log(b)
		t.Log(b_MESSAGE_WITH_XOR_MAPPED_ATTR)
		t.Error("Pack failed")
	}
}

func TestUnPackXorMappedAddress(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_XOR_MAPPED_ATTR)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	mapped := m.Attributes[0].(*XORMappedAddress)
	if mapped.Family != 0x01 {
		t.Error("Family mismatch")
	}
	if mapped.Port != 1024 {
		t.Error("Port mismatch")
	}
	if !mapped.IP.Equal(net.ParseIP("192.168.2.1")) {
		t.Error("IP mismatch")
	}
}
