package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_UNKNOWN_ATTRIBUTES = []byte{
	0x01, 0x01, 0x00, 0x0C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x0A, 0x00, 0x06, // Unknown Attributes
	0x80, 0x40, 0x80, 0x41,
	0x80, 0x42, 0x00, 0x00,
}

func TestPackUnknownAttributes(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	unknown := new(UnknownAttributes)
	unknown.Attributes = []uint16{32832, 32833, 32834}
	m.AddAttribute(unknown)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 32 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_UNKNOWN_ATTRIBUTES) {
		t.Log(b)
		t.Log(b_MESSAGE_WITH_UNKNOWN_ATTRIBUTES)
		t.Error("Pack failed")
	}
}

func TestUnPackUnknownAttributes(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_UNKNOWN_ATTRIBUTES)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	unknown := m.Attributes[0].(*UnknownAttributes)
	if len(unknown.Attributes) != 3 {
		t.Error("Attribute length is wrong")
	}
	if unknown.Attributes[0] != 32832 || unknown.Attributes[1] != 32833 || unknown.Attributes[2] != 32834 {
		t.Log(unknown.Attributes)
		t.Error("Attribute values are wrong")
	}
}

func TestUnPackMessageWithUnknownAttributes(t *testing.T) {
	var b = []byte{
		0x01, 0x01, 0x00, 0x30,
		0x21, 0x12, 0xA4, 0x42,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x81, 0x01, 0x00, 0x07, // Unknown Attributes Type
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x00,
		0x81, 0x02, 0x00, 0x0A, // Unknown Attributes Type
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x00,
		0x55, 0x66, 0x00, 0x00,
	}

	m := new(Message)
	err := m.UnPack(b)
	if err != nil {
		t.Error(err)
	}
	if len(m.UnknownAttributes) != 2 {
		t.Error("Wrong number of attributes")
	}
	if m.UnknownAttributes[0] != 33025 || m.UnknownAttributes[1] != 33026 {
		t.Error("Attribute values are wrong")
	}
}
