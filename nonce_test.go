package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_NONCE = []byte{
	0x01, 0x01, 0x00, 0x0C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x15, 0x00, 0x06, // Nonce
	0x43, 0x41, 0x47, 0x44, // CAGDAS
	0x41, 0x53, 0x00, 0x00,
}

func TestPackNonce(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	nonce := new(Nonce)
	nonce.Value = "CAGDAS"
	m.AddAttribute(nonce)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 32 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_NONCE) {
		t.Log(b)
		t.Log(b_MESSAGE_WITH_NONCE)
		t.Error("Pack failed")
	}
}

func TestUnPackNonce(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_NONCE)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	nonce := m.Attributes[0].(*Nonce)
	if nonce.Length() != 6 {
		t.Error("Length doesn't match")
	}
	if nonce.Value != "CAGDAS" {
		t.Error("Nonce doesn't match")
	}
}
