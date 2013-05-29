package stun

import (
	"errors"
	"net"
)

type MappedAddress struct {
	Family byte
	Port   uint16
	IP     net.IP
}

func (m *MappedAddress) Type() uint16 {
	return ATTR_TYPE_MAPPED_ADDRESS
}

func (m *MappedAddress) Length() uint16 {
	if m.Family == 0x01 {
		return 8
	} else {
		return 20
	}
}

func (m *MappedAddress) Pack(b []byte) error {
	b = b[4:]
	if m.Family == 0x01 {
		if len(b) < 8 {
			return errors.New("Buffer too short for IPv4")
		}
		b[0] = 0
		b[1] = 0x01 // Family
		putUint16(b[2:4], m.Port)
		i := copy(b[4:8], m.IP.To4())
		if i != 4 {
			return errors.New("Copy failed")
		}
		return nil
	} else if m.Family == 0x02 {
		if len(b) < 20 {
			return errors.New("Buffer too short for IPv6")
		}
		b[1] = 0x02 // Family
		putUint16(b[2:4], m.Port)
		i := copy(b[4:20], m.IP)
		if i != 16 {
			return errors.New("Copy failed")
		}
		return nil
	}
	return errors.New("Undefined Family")
}

func (m *MappedAddress) UnPack(b []byte) error {
	b = b[4:]
	if len(b) < 8 {
		return errors.New("Buffer too short")
	}
	m.Family = b[1]
	if m.Family == 0x02 && len(b) < 20 {
		return errors.New("Buffer is too short for IPv6")
	}
	m.Port = toUint16(b[2:4])
	if m.Family == 0x01 {
		m.IP = net.IPv4(b[4], b[5], b[6], b[7])
	} else {
		m.IP = make(net.IP, 16)
		i := copy(m.IP, b[4:20])
		if i != 16 {
			return errors.New("Copy failed")
		}
	}
	return nil
}
