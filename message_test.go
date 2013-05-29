package stun

import (
	"bytes"
	"net"
	"testing"
)

var b_BINDING_REQUEST_HEADER_ONLY = []byte{
	0x00, 0x01, 0x00, 0x00,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
}

var b_BINDING_RESPONSE_HEADER_ONLY = []byte{
	0x01, 0x01, 0x00, 0x00,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
}

func TestUnPackRequestHeaderOnly(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_BINDING_REQUEST_HEADER_ONLY)
	if err != nil {
		t.Error(err)
	}
	if m.Header.Type != BINDING_REQUEST {
		t.Error("Message Type is wrong")
	}
	if m.Header.Length != 0 {
		t.Error("Message Length is not zero")
	}
	if m.Header.Cookie != RFC5389_COOKIE {
		t.Error("Cookie is not equal to RFC5389 COOKIE")
	}
	if !bytes.Equal(m.Header.TransactionId[:], b_BINDING_REQUEST_HEADER_ONLY[8:20]) {
		t.Error("Transaction Id does not match")
	}
}

func TestUnPackResponseHeaderOnly(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_BINDING_RESPONSE_HEADER_ONLY)
	if err != nil {
		t.Error(err)
	}
	if m.Header.Type != BINDING_RESPONSE {
		t.Error("Message Type is wrong")
	}
	if m.Header.Length != 0 {
		t.Error("Message Length is not zero")
	}
	if m.Header.Cookie != RFC5389_COOKIE {
		t.Error("Cookie is not equal to RFC5389 COOKIE")
	}
	if !bytes.Equal(m.Header.TransactionId[:], b_BINDING_RESPONSE_HEADER_ONLY[8:20]) {
		t.Error("Transaction Id does not match")
	}
}

func TestPackRequestHeaderOnly(t *testing.T) {
	m, _ := New(BINDING_REQUEST, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 20 {
		t.Error("Buffer length is wrong")
	}
	err := m.Pack(b)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b, b_BINDING_REQUEST_HEADER_ONLY) {
		t.Log(b)
		t.Log(b_BINDING_REQUEST_HEADER_ONLY)
		t.Error("Pack failed")
	}
}

func TestPackResponseHeaderOnly(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 20 {
		t.Error("Buffer length is wrong")
	}
	err := m.Pack(b)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b, b_BINDING_RESPONSE_HEADER_ONLY) {
		t.Log(b)
		t.Log(b_BINDING_RESPONSE_HEADER_ONLY)
		t.Error("Pack failed")
	}
}

var b_BINDING_RESPONSE_WITH_MAPPED_ADDRESS = []byte{
	0x01, 0x01, 0x00, 0x0C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x01, 0x00, 0x08, // Mapped Address
	0x00, 0x01, 0x04, 0x00,
	0xC0, 0xA8, 0x00, 0x01, // 192.168.0.1
}

func TestUnPackWithAttribute(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_BINDING_RESPONSE_WITH_MAPPED_ADDRESS)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Attribute count is wrong")
	}
	if m.Attributes[0].Type() != ATTR_TYPE_MAPPED_ADDRESS {
		t.Error("Attribute type is wrong")
	}
	if m.Attributes[0].Length() != 8 {
		t.Error("Attribute length is wrong")
	}
	mapped := m.Attributes[0].(*MappedAddress)
	if mapped.Family != 0x01 {
		t.Error("Wrong Family")
	}
	if mapped.Port != 1024 {
		t.Error("Wrong Port", mapped.Port)
	}
	if mapped.IP.String() != "192.168.0.1" {
		t.Error("Wrong IP", mapped.IP)
	}
}

func TestPackWithAttribute(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)

	mapped := new(MappedAddress)
	mapped.Family = 0x01
	mapped.Port = 1024
	mapped.IP = net.ParseIP("192.168.0.1")
	t.Log(mapped.IP)
	m.AddAttribute(mapped)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 32 {
		t.Error("Buffer length is wrong")
	}
	err := m.Pack(b)
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal(b, b_BINDING_RESPONSE_WITH_MAPPED_ADDRESS) == false {
		t.Log(b)
		t.Log(b_BINDING_RESPONSE_WITH_MAPPED_ADDRESS)
		t.Error("Pack failed")
	}
}
