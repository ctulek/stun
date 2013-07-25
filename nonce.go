package stun

import (
	"errors"
	"fmt"
)

type Nonce struct {
	Value string
}

func (n *Nonce) Type() uint16 {
	return ATTR_TYPE_NONCE
}

func (n *Nonce) Length() uint16 {
	return uint16(len(n.Value))
}

func (n *Nonce) Pack(b []byte) error {
	b = b[4:]
	if len(b) < int(n.Length()) {
		return errors.New("Buffer is too short for nonce")
	}
	i := copy(b[:], n.Value)
	if i != int(n.Length()) {
		return errors.New("Copy failed")
	}
	return nil
}

func (n *Nonce) UnPack(b []byte) error {
	l := int(toUint16(b[2:4]))
	if len(b) < l+4 {
		return errors.New("Buffer is shorter than declared")
	}
	b = b[4:]
	n.Value = string(b[0:l])
	return nil
}

func (n *Nonce) String() string {
	return fmt.Sprintf("Nonce: %s", n.Value)
}
