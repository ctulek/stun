/**
TODO:
- Implement RTO according to RFC5389 Section 7.2.1
*/
package stun

import (
	"errors"
	"fmt"
	"net"
)

type ClientOpts struct {
	Software string
}

// Calls the stun server given with host, port and options.
//
// If the call is successful it returns caller's IP and Port information
func Call(host string, port int, options ClientOpts) (addr net.UDPAddr, err error) {
	remoteAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return
	}
	response, err := SendBindingRequest(conn, remoteAddr, options)
	if err != nil {
		return
	}
	if response.Header.IsValid() == false {
		err = errors.New("Server returned an invalid response")
		return
	}
	for _, attr := range response.Attributes {
		if mapped, ok := attr.(*MappedAddress); ok {
			addr = net.UDPAddr{IP: mapped.IP, Port: int(mapped.Port)}
			return
		}
	}
	err = errors.New("Can't find Mapped Address attribute")
	return
}

func SendBindingRequest(conn *net.UDPConn, address *net.UDPAddr, options ClientOpts) (*Message, error) {
	m, err := NewBindingRequest()
	if err != nil {
		return nil, err
	}
	software := new(Software)
	software.Value = options.Software
	m.AddAttribute(software)
	response, err := SendMessage(conn, address, m)
	return response, err
}

func SendMessage(conn *net.UDPConn, address *net.UDPAddr, m *Message) (*Message, error) {
	// Send UDP MESSAGE
	b := make([]byte, m.MinBufferSize())
	m.Pack(b)
	conn.Write(b)
	// Wait for reply
	b = make([]byte, 512)
	conn.Read(b)
	response := new(Message)
	err := response.UnPack(b)
	return response, err
}
