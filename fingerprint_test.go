package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_FINGERPRINT = []byte{
	0x01, 0x01, 0x00, 0x24,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x80, 0x28, 0x00, 0x20, // Finger Print
	0x43, 0x41, 0x47, 0x44,
	0x41, 0x53, 0x15, 0x08,
	0x43, 0x41, 0x47, 0x44,
	0x41, 0x53, 0x15, 0x08,
	0x41, 0x53, 0x15, 0x08,
	0x41, 0x53, 0x15, 0x08,
	0x41, 0x53, 0x15, 0x08,
	0x41, 0x53, 0x15, 0x08,
}

func TestPackFingerprint(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	fingerprint := new(Fingerprint)
	fingerprint.Value = string(b_MESSAGE_WITH_FINGERPRINT[24:])
	m.AddAttribute(fingerprint)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 56 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_FINGERPRINT) {
		t.Log(len(fingerprint.Value))
		t.Log(b)
		t.Log(b_MESSAGE_WITH_FINGERPRINT)
		t.Error("Pack failed")
	}
}

func TestUnPackFingerprint(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_FINGERPRINT)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	fingerprint := m.Attributes[0].(*Fingerprint)
	if fingerprint.Length() != 32 {
		t.Error("Length doesn't match")
	}
	val := make([]byte, len(fingerprint.Value))
	copy(val, fingerprint.Value)
	if !bytes.Equal(b_MESSAGE_WITH_FINGERPRINT[24:], val) {
		t.Log(val)
		t.Log(b_MESSAGE_WITH_FINGERPRINT[24:])
		t.Error("Value doesn't match")
	}
}
