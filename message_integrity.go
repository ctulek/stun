package stun

import (
	"errors"
	"fmt"
)

type MessageIntegrity struct {
	Value string
}

func (u *MessageIntegrity) Type() uint16 {
	return ATTR_TYPE_MESSAGE_INTEGRITY
}

func (u *MessageIntegrity) Length() uint16 {
	return 20
}

func (u *MessageIntegrity) Pack(b []byte) error {
	b = b[4:]
	if len(b) < 20 {
		return errors.New("Buffer is too short")
	}
	i := copy(b[:], u.Value)
	if i != 20 {
		return errors.New("Copy failed")
	}
	return nil
}

func (u *MessageIntegrity) UnPack(b []byte) error {
	b = b[4:]
	if len(b) < 20 {
		return errors.New("Buffer is too short")
	}
	u.Value = string(b[0:20])
	return nil
}

func (m *MessageIntegrity) String() string {
	return fmt.Sprintf("Message Integrity: %s", m.Value)
}
