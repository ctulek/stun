/**
TODO:
- Implement RTO according to RFC5389 Section 7.2.1
*/
package stun

import (
	"net"
)

func SendBindingRequest(conn *net.UDPConn, address *net.UDPAddr) (*Message, error) {
	m, err := NewBindingRequest()
	if err != nil {
		return nil, err
	}
	software := new(Software)
	software.Value = "Go Client"
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
