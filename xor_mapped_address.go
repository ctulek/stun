package stun

import (
	"errors"
	"net"
)

type XORMappedAddress struct {
	Family byte
	Port   uint16
	IP     net.IP
}

func (x *XORMappedAddress) Type() uint16 {
	return ATTR_TYPE_XOR_MAPPED_ADDRESS
}

func (x *XORMappedAddress) Length() uint16 {
	if x.Family == 0x01 {
		return 8
	} else {
		return 20
	}
}

func (x *XORMappedAddress) Pack(b []byte) error {
	b = b[4:]
	if x.Family == 0x01 {
		if len(b) < 8 {
			return errors.New("Buffer too short for IPv4")
		}
		b[1] = 0x01 // Family
		putUint16(b[2:4], xorPort(x.Port))
		i := copy(b[4:8], xorIP(x.IP.To4()))
		if i != 4 {
			return errors.New("Copy failed")
		}
		return nil
	} else if x.Family == 0x02 {
		if len(b) < 20 {
			return errors.New("Buffer too short for IPv6")
		}
		b[1] = 0x02 // Family
		putUint16(b[2:4], xorPort(x.Port))
		i := copy(b[4:20], xorIP(x.IP))
		if i != 16 {
			return errors.New("Copy failed")
		}
		return nil
	}
	return errors.New("Undefined Family")
}

func xorPort(p uint16) uint16 {
	var cookie [4]byte
	putUint32(cookie[:], RFC5389_COOKIE)
	var bytes [2]byte
	putUint16(bytes[:], p)
	for i := 0; i < len(bytes); i++ {
		bytes[i] = bytes[i] ^ cookie[i]
	}
	p = toUint16(bytes[:])
	return p
}

func xorIP(ip []byte) net.IP {
	var cookie [4]byte
	putUint32(cookie[:], RFC5389_COOKIE)
	for i := 0; i < len(ip); i++ {
		ip[i] = ip[i] ^ cookie[i%4]
	}

	return ip
}

func (x *XORMappedAddress) UnPack(b []byte) error {
	b = b[4:]
	if len(b) < 8 {
		return errors.New("Buffer too short")
	}
	x.Family = b[1]
	if x.Family == 0x02 && len(b) < 20 {
		return errors.New("Buffer is too short for IPv6")
	}
	x.Port = toUint16(b[2:4])
	x.Port = xorPort(x.Port)
	if x.Family == 0x01 {
		x.IP = make(net.IP, 4)
		i := copy(x.IP, b[4:8])
		if i != 4 {
			return errors.New("Copy failed")
		}
		x.IP = xorIP(x.IP)
	} else {
		x.IP = make(net.IP, 16)
		i := copy(x.IP, b[4:20])
		if i != 16 {
			return errors.New("Copy failed")
		}
	}
	return nil
}
