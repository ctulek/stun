package stun

import (
	"errors"
)

const (
	ERR_TRY_ALTERNATE = 300
	ERR_BAD_REQUEST   = 400
	ERR_UNAUTHORIZED  = 401
	ERR_UNKNOWN_ATTR  = 420
	ERR_STALE_NONCE   = 438
	ERR_SERVER_ERROR  = 500
)

type ErrorCode struct {
	Code   int
	Phrase string
}

func (e *ErrorCode) Type() uint16 {
	return ATTR_TYPE_ERROR_CODE
}

func (e *ErrorCode) Length() uint16 {
	return uint16(len(e.Phrase) + 4)
}

func (e *ErrorCode) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(e.Length()) {
		errors.New("Buffer is too short")
	}
	class := e.Code / 100
	number := e.Code - class*100
	b[2] = byte(class) & 0x7
	b[3] = byte(number)
	copy(b[4:], e.Phrase)
	return nil
}

func (e *ErrorCode) UnPack(b []byte) error {
	strlen := int(toUint16(b[2:4])) - 4
	if len(b[8:]) < strlen {
		return errors.New("Buffer is too short")
	}
	b = b[4:]
	class, number := int(b[2]&0x7)*100, int(b[3])
	e.Code = class + number
	e.Phrase = string(b[4 : 4+strlen])
	return nil
}
