// TODO: RTO Algorithm RFC2988
// TODO: Hard ICMP error RFC1122
package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func toUint16(bytes []byte) uint16 {
	return binary.BigEndian.Uint16(bytes)
}

func toUint32(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

func putUint16(bytes []byte, n uint16) {
	binary.BigEndian.PutUint16(bytes, n)
}

func putUint32(bytes []byte, n uint32) {
	binary.BigEndian.PutUint32(bytes, n)
}

const (
	RETRY_MAX = 7
	RTO_INIT  = 500 // ms
)

var (
	BINDING_REQUEST    = toUint16([]byte{0x00, 0x01})
	BINDING_RESPONSE   = toUint16([]byte{0x01, 0x01})
	BINDING_INDICATION = toUint16([]byte{0x00, 0x11})
	BINDING_ERROR      = toUint16([]byte{0x01, 0x11})
	RFC5389_COOKIE     = toUint32([]byte{0x21, 0x12, 0xA4, 0x42})
)

type Message struct {
	Header            Header
	Attributes        []Attribute
	RTO               int
	MaxRetry          int
	UnknownAttributes []uint16
}

type Header struct {
	Type          uint16
	Length        uint16
	Cookie        uint32
	TransactionId [12]byte
}

type Attribute interface {
	Type() uint16
	Length() uint16
	Pack([]byte) error
	UnPack([]byte) error
	String() string
}

var (
	// Comprehension-required
	ATTR_TYPE_MAPPED_ADDRESS     = toUint16([]byte{0x00, 0x01})
	ATTR_TYPE_USER_NAME          = toUint16([]byte{0x00, 0x06})
	ATTR_TYPE_MESSAGE_INTEGRITY  = toUint16([]byte{0x00, 0x08})
	ATTR_TYPE_ERROR_CODE         = toUint16([]byte{0x00, 0x09})
	ATTR_TYPE_UNKNOWN_ATTRIBUTES = toUint16([]byte{0x00, 0x0A})
	ATTR_TYPE_REALM              = toUint16([]byte{0x00, 0x14})
	ATTR_TYPE_NONCE              = toUint16([]byte{0x00, 0x15})
	ATTR_TYPE_XOR_MAPPED_ADDRESS = toUint16([]byte{0x00, 0x20})
	// Comprehension-optional
	ATTR_TYPE_SOFTWARE         = toUint16([]byte{0x80, 0x22})
	ATTR_TYPE_ALTERNATE_SERVER = toUint16([]byte{0x80, 0x23})
	ATTR_TYPE_FINGERPRINT      = toUint16([]byte{0x80, 0x28})
)

func (m *Message) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(
		fmt.Sprintf("Header:\n%s\n", m.Header.String()))
	buffer.WriteString(
		fmt.Sprintf("RTO: %d Max Retry: %d", m.RTO, m.MaxRetry))
	if len(m.UnknownAttributes) > 0 {
		buffer.WriteString(
			fmt.Sprintf("Unknown Attributes: %v",
				m.UnknownAttributes))
	}
	buffer.WriteString("\n\n")

	for _, value := range m.Attributes {
		buffer.WriteString(fmt.Sprintf("%s\n", value.String()))
	}
	return buffer.String()
}

func (h *Header) String() string {
	var buffer bytes.Buffer
	var typeString string
	switch h.Type {
	case BINDING_REQUEST:
		typeString = "Binding Request"
	case BINDING_RESPONSE:
		typeString = "Binding Response"
	case BINDING_INDICATION:
		typeString = "Binding Indication"
	case BINDING_ERROR:
		typeString = "Binding Error"
	}

	buffer.WriteString(fmt.Sprintf("Type   : %s\n", typeString))
	buffer.WriteString(fmt.Sprintf("Len    : %d\n", h.Length))
	buffer.WriteString(fmt.Sprintf("Cookie : %x\n", h.Cookie))
	buffer.WriteString(fmt.Sprintf("Txn. ID: %x\n", h.TransactionId))

	return buffer.String()
}

func (h *Header) IsValid() bool {
	var bits1 [2]byte
	putUint16(bits1[:], h.Type)
	var bits2 [2]byte
	putUint16(bits2[:], h.Length)
	return (bits1[0]&0xC0) == 0 && (bits2[1]&0x03) == 0
}

func (s *Header) IsRFC5389Compliant() bool {
	return s.Cookie == RFC5389_COOKIE
}

func GenerateTransactionId() (id [12]byte, err error) {
	n, err := io.ReadFull(rand.Reader, id[:])
	if n != len(id) {
		err = errors.New("Id Generation Failed")
	}
	return
}

func (s *Message) MinBufferSize() int {
	size := 20
	for _, v := range s.Attributes {
		size += addPadding(int(v.Length())) + 4 // 4 is att. header
	}
	return size
}

func addPadding(l int) int {
	if l%4 == 0 {
		return l
	} else {
		return (l/4)*4 + 4
	}
}

func (msg *Message) UnPack(b []byte) (err error) {
	if len(b) < 20 {
		err = errors.New("Buffer is too short for Message")
		return
	}
	msg.Header.Type = toUint16(b[0:2])
	msg.Header.Length = toUint16(b[2:4])
	msg.Header.Cookie = toUint32(b[4:8])
	copy(msg.Header.TransactionId[:], b[8:20])
	if msg.Header.Length > 0 {
		pos := 20
		if pos+4 > len(b) {
			return errors.New("Buffer is too short")
		}
		for pos < len(b) && pos < int(msg.Header.Length)+20 {
			l := int(toUint16(b[pos+2 : pos+4]))
			if pos+l+4 > len(b) {
				return errors.New("Buffer is too short")
			}
			attr, err := msg.attributeFactory(b[pos:])
			if err != nil {
				pos += addPadding(l) + 4
				continue
			}
			err = attr.UnPack(b[pos:])
			if err != nil {
				return err
			}
			pos += addPadding(int(attr.Length())) + 4
			msg.Attributes = append(msg.Attributes, attr)
		}
	}
	return
}

func (msg *Message) Pack(b []byte) (err error) {
	if len(b) < msg.MinBufferSize() {
		err = errors.New("Buffer is not big enough")
		return
	}
	msg.Header.Length = uint16(msg.MinBufferSize() - 20)
	putUint16(b[0:2], msg.Header.Type)
	putUint16(b[2:4], msg.Header.Length)
	putUint32(b[4:8], msg.Header.Cookie)
	copy(b[8:20], msg.Header.TransactionId[:])
	pos := 20
	for _, attr := range msg.Attributes {
		putUint16(b[pos:pos+2], attr.Type())
		putUint16(b[pos+2:pos+4], attr.Length())
		err = attr.Pack(b[pos:])
		if err != nil {
			return
		}
		pos += addPadding(int(attr.Length())) + 4
	}
	return
}

func (msg *Message) AddAttribute(attr Attribute) {
	msg.Attributes = append(msg.Attributes, attr)
	msg.Header.Length += attr.Length() + 4
}

func (msg *Message) AddIntegrityCheck() {
	// TODO: Implement this according to
	// http://tools.ietf.org/html/rfc5389#section-15.4
}

func (msg *Message) CheckIntegrity() {
	// TODO: Implement this according to
	// http://tools.ietf.org/html/rfc5389#section-15.4
}

func (msg *Message) AddFingerprint() {
	// TODO: Implement this according to
	// http://tools.ietf.org/html/rfc5389#section-15.5
}

func (msg *Message) CheckFingerprint() {
	// TODO: Implement this according to
	// http://tools.ietf.org/html/rfc5389#section-15.5
}

func (msg *Message) attributeFactory(b []byte) (Attribute, error) {
	t := toUint16(b[0:2])
	switch t {
	case ATTR_TYPE_MAPPED_ADDRESS:
		return new(MappedAddress), nil
	case ATTR_TYPE_XOR_MAPPED_ADDRESS:
		return new(XORMappedAddress), nil
	case ATTR_TYPE_USER_NAME:
		return new(Username), nil
	case ATTR_TYPE_MESSAGE_INTEGRITY:
		return new(MessageIntegrity), nil
	case ATTR_TYPE_FINGERPRINT:
		return new(Fingerprint), nil
	case ATTR_TYPE_ERROR_CODE:
		return new(ErrorCode), nil
	case ATTR_TYPE_REALM:
		return new(Realm), nil
	case ATTR_TYPE_NONCE:
		return new(Nonce), nil
	case ATTR_TYPE_UNKNOWN_ATTRIBUTES:
		return new(UnknownAttributes), nil
	case ATTR_TYPE_SOFTWARE:
		return new(Software), nil
	case ATTR_TYPE_ALTERNATE_SERVER:
		return new(AlternateServer), nil
	default:
		msg.UnknownAttributes = append(msg.UnknownAttributes, t)
		return nil, errors.New("Undefined Attribute Type")
	}
}

func New(Type uint16, cookie uint32, id [12]byte, rto int, retry int) (msg *Message, err error) {
	msg = new(Message)
	msg.Header.Type = Type
	msg.Header.Cookie = cookie
	msg.Header.TransactionId = id
	msg.RTO = rto
	msg.MaxRetry = retry
	return msg, nil
}

func NewBindingRequest() (msg *Message, err error) {
	id, err := GenerateTransactionId()
	if err != nil {
		return
	}
	msg, err = New(BINDING_REQUEST, RFC5389_COOKIE, id, RTO_INIT, RETRY_MAX)
	if err != nil {
		return nil, err
	}
	return
}
