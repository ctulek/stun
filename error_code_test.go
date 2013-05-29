package stun

import (
	"bytes"
	"testing"
)

var b_MESSAGE_WITH_ERROR_CODE = []byte{
	0x01, 0x01, 0x00, 0x1C,
	0x21, 0x12, 0xA4, 0x42,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C,
	0x00, 0x09, 0x00, 0x15, // Error Code
	0x00, 0x00, 0x04, 0x14, // 420
	0x55, 0x6e, 0x6b, 0x6e,
	0x6f, 0x77, 0x6e, 0x20,
	0x41, 0x74, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74,
	0x65, 0x00, 0x00, 0x00,
}

func TestPackErrorCode(t *testing.T) {
	m, _ := New(BINDING_RESPONSE, RFC5389_COOKIE,
		[12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		RTO_INIT, RETRY_MAX)
	errorCode := new(ErrorCode)
	errorCode.Code = 420
	errorCode.Phrase = "Unknown Attribute"
	m.AddAttribute(errorCode)

	b := make([]byte, m.MinBufferSize())
	if len(b) != 48 {
		t.Error("Buffer size is wrong")
	}
	m.Pack(b)
	if !bytes.Equal(b, b_MESSAGE_WITH_ERROR_CODE) {
		t.Log(errorCode.Length())
		t.Log(b)
		t.Log(b_MESSAGE_WITH_ERROR_CODE)
		t.Error("Pack failed")
	}
}

func TestUnPackErrorCode(t *testing.T) {
	m := new(Message)
	err := m.UnPack(b_MESSAGE_WITH_ERROR_CODE)
	if err != nil {
		t.Error(err)
	}
	if len(m.Attributes) != 1 {
		t.Error("Wrong number of attributes")
	}
	errorCode := m.Attributes[0].(*ErrorCode)
	if errorCode.Length() != 21 {
		t.Error("Length doesn't match")
	}
	if errorCode.Code != 420 {
		t.Log(errorCode.Code)
		t.Error("Code doesn't match")
	}
	if errorCode.Phrase != "Unknown Attribute" {
		t.Error("Phrase doesn't match")
	}
}
