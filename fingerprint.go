package stun

import (
	"errors"
	"fmt"
)

type Fingerprint struct {
	Value string
}

func (f *Fingerprint) Type() uint16 {
	return ATTR_TYPE_FINGERPRINT
}

func (f *Fingerprint) Length() uint16 {
	return 32
}

func (f *Fingerprint) Pack(b []byte) error {
	b = b[4:]
	if len(b) < 32 {
		return errors.New("Buffer is too short")
	}
	i := copy(b[:], f.Value)
	if i != 32 {
		return errors.New("Copy failed")
	}
	return nil
}

func (f *Fingerprint) UnPack(b []byte) error {
	b = b[4:]
	if len(b) < 32 {
		return errors.New("Buffer is too short")
	}
	f.Value = string(b[0:32])
	return nil
}

func (f *Fingerprint) String() string {
	return fmt.Sprintf("Finger Print: %s", f.Value)
}
