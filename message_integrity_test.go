package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_INTEGRITY = []byte{
	0x01, 0x01, 0x00, 0x18,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x08, 0x00, 0x14, // Message Integrity
	0x43, 0x41, 0x47, 0x44,
	0x41, 0x53, 0x15, 0x08,
	0x43, 0x41, 0x47, 0x44,
	0x41, 0x53, 0x15, 0x08,
	0x41, 0x53, 0x15, 0x08,
}

func TestPackMessageIntegrity(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	integrity := new(MessageIntegrity)
	integrity.Value = string(b_MESSAGE_WITH_INTEGRITY[24:])
	m.AddAttribute(integrity)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 44 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_INTEGRITY) {
		t.Log(b)
		t.Log(b_MESSAGE_WITH_INTEGRITY)
		t.Error("Pack failed")
	}
}

func TestUnPackMessageIntegrity(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_INTEGRITY)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	integrity := m.Attributes[0].(*MessageIntegrity)
	if integrity.Length() != 20 {
		t.Error("Length doesn't match")
	}
	val := make([]byte, len(integrity.Value))
	copy(val, integrity.Value)
	if !bytes.Equal(b_MESSAGE_WITH_INTEGRITY[24:], val) {
		t.Error("Value doesn't match")
	}
}
