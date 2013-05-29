package stun

import (
	"net"
	"testing"
)

func TestMappedAddress(t *testing.T) {
	m, _ := NewBindingRequest()
	mapped := new(MappedAddress)
	mapped.Family = 0x01
	mapped.Port = 80
	mapped.IP = net.ParseIP("192.168.1.1")
	t.Log(mapped.IP)
	m.AddAttribute(mapped)

	b := make([]byte, m.MinBufferSize())
	err := m.Pack(b)
	if err != nil {
		t.Error(err)
	}
	t.Log(len(b), b)

	m2 := new(Message)
	m2.UnPack(b)

	if len(m2.Attributes) != 1 {
		t.Error("Attribute count is wrong", len(m2.Attributes))
	}

	mapped2 := m2.Attributes[0].(*MappedAddress)

	if mapped2.Family != mapped.Family {
		t.Error("Unpack failed: Wrong Family")
	}

	if mapped2.Port != mapped.Port {
		t.Error("Unpack failed: Wrong Port")
	}

	if !mapped2.IP.Equal(mapped.IP) {
		t.Error("Unpack failed: Wrong IP")
	}

	if mapped2.IP.To4() == nil {
		t.Error("Wrong API type")
	}
}
