package stun

import (
	"errors"
)

type Username struct {
	Value string
}

func (u *Username) Type() uint16 {
	return ATTR_TYPE_USER_NAME
}

func (u *Username) Length() uint16 {
	return uint16(len(u.Value))
}

func (u *Username) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(u.Length()) {
		return errors.New("Buffer is too short for username")
	}
	i := copy(b[:], u.Value)
	if i != int(u.Length()) {
		return errors.New("Copy failed")
	}
	return nil
}

func (u *Username) UnPack(b []byte) error {
	l := int(toUint16(b[2:4]))
	if len(b) < l+4 {
		return errors.New("Buffer is shorter than declared")
	}
	b = b[4:]
	u.Value = string(b[0:l])
	return nil
}
