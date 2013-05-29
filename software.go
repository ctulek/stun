package stun

import (
	"errors"
)

type Software struct {
	Value string
}

func (s *Software) Type() uint16 {
	return ATTR_TYPE_SOFTWARE
}

func (s *Software) Length() uint16 {
	return uint16(len(s.Value))
}

func (s *Software) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(s.Length()) {
		return errors.New("Buffer is too short for software")
	}
	i := copy(b[:], s.Value)
	if i != int(s.Length()) {
		return errors.New("Copy failed")
	}
	return nil
}

func (s *Software) UnPack(b []byte) error {
	l := int(toUint16(b[2:4]))
	if len(b) < l+4 {
		return errors.New("Buffer is shorter than declared")
	}
	b = b[4:]
	s.Value = string(b[0:l])
	return nil
}
