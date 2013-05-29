package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_SOFTWARE = []byte{
	0x01, 0x01, 0x00, 0x10,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x80, 0x22, 0x00, 0x0B, // Software
	0x54, 0x45, 0x53, 0x54, // TEST CLIENT
	0x20, 0x43, 0x4c, 0x49,
	0x45, 0x4e, 0x54, 0x00,
}

func TestPackSoftware(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	software := new(Software)
	software.Value = "TEST CLIENT"
	m.AddAttribute(software)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 36 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_SOFTWARE) {
		t.Log(b)
		t.Log(b_MESSAGE_WITH_SOFTWARE)
		t.Error("Pack failed")
	}
}

func TestUnPackSoftware(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_SOFTWARE)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	software := m.Attributes[0].(*Software)
	if software.Length() != 11 {
		t.Error("Length doesn't match")
	}
	if software.Value != "TEST CLIENT" {
		t.Error("Software doesn't match")
	}
}
