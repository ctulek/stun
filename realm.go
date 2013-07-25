package stun

import (
	"errors"
	"fmt"
)

type Realm struct {
	Value string
}

func (r *Realm) Type() uint16 {
	return ATTR_TYPE_REALM
}

func (r *Realm) Length() uint16 {
	return uint16(len(r.Value))
}

func (r *Realm) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(r.Length()) {
		return errors.New("Buffer is too short for realm")
	}
	i := copy(b[:], r.Value)
	if i != int(r.Length()) {
		return errors.New("Copy failed")
	}
	return nil
}

func (r *Realm) UnPack(b []byte) error {
	l := int(toUint16(b[2:4]))
	if len(b) < l+4 {
		return errors.New("Buffer is shorter than declared")
	}
	b = b[4:]
	r.Value = string(b[0:l])
	return nil
}

func (r *Realm) String() string {
	return fmt.Sprintf("Realm: %s", r.Value)
}
