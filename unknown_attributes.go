package stun

import (
	"errors"
)

type UnknownAttributes struct {
	Attributes []uint16
}

func (u *UnknownAttributes) Type() uint16 {
	return ATTR_TYPE_UNKNOWN_ATTRIBUTES
}

func (u *UnknownAttributes) Length() uint16 {
	return uint16(len(u.Attributes) * 2)
}

func (u *UnknownAttributes) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(u.Length()) {
		return errors.New("Buffer is too short")
	}
	for i := 0; i < len(u.Attributes)*2; i += 2 {
		putUint16(b[i:i+2], u.Attributes[i/2])
	}
	return nil
}

func (u *UnknownAttributes) UnPack(b []byte) error {
	l := toUint16(b[2:4])
	b = b[4:]
	if len(b) < int(l) {
		return errors.New("Buffer is too short")
	}
	u.Attributes = make([]uint16, 0, l/2)
	for i := 0; i < cap(u.Attributes)*2; i += 2 {
		u.Attributes = append(u.Attributes, toUint16(b[i:i+2]))
	}
	return nil
}

func (u *UnknownAttributes) String() string {
	return "Not implemented"
}
