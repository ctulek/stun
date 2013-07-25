package stun

import (
	"errors"
	"fmt"
	"net"
)

type AlternateServer struct {
	Family byte
	Port   uint16
	IP     net.IP
}

func (a *AlternateServer) Type() uint16 {
	return ATTR_TYPE_ALTERNATE_SERVER
}

func (a *AlternateServer) Length() uint16 {
	if a.Family == 0x01 {
		return 8
	} else {
		return 20
	}
}

func (a *AlternateServer) Pack(b []byte) error {
	b = b[4:]
	if a.Family == 0x01 {
		if len(b) < 8 {
			return errors.New("Buffer too short for IPv4")
		}
		b[0] = 0
		b[1] = 0x01 // Family
		putUint16(b[2:4], a.Port)
		i := copy(b[4:8], a.IP.To4())
		if i != 4 {
			return errors.New("Copy failed")
		}
		return nil
	} else if a.Family == 0x02 {
		if len(b) < 20 {
			return errors.New("Buffer too short for IPv6")
		}
		b[1] = 0x02 // Family
		putUint16(b[2:4], a.Port)
		i := copy(b[4:20], a.IP)
		if i != 16 {
			return errors.New("Copy failed")
		}
		return nil
	}
	return errors.New("Undefined Family")
}

func (a *AlternateServer) UnPack(b []byte) error {
	b = b[4:]
	if len(b) < 8 {
		return errors.New("Buffer too short")
	}
	a.Family = b[1]
	if a.Family == 0x02 && len(b) < 20 {
		return errors.New("Buffer is too short for IPv6")
	}
	a.Port = toUint16(b[2:4])
	if a.Family == 0x01 {
		a.IP = net.IPv4(b[4], b[5], b[6], b[7])
	} else {
		a.IP = make(net.IP, 16)
		i := copy(a.IP, b[4:20])
		if i != 16 {
			return errors.New("Copy failed")
		}
	}
	return nil
}

func (a *AlternateServer) String() string {
	var family string
	switch a.Family {
	case 1:
		family = "IPv4"
	case 2:
		family = "IPv6"
	}

	return fmt.Sprintf("Alternate Server: %s %s:%d", family, a.IP, a.Port)
}
