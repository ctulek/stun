/**
TODO:
- Implement RTO according to RFC5389 Section 7.2.1
*/
package stun

import (
	"net"
	"fmt"
    "log"
)

func Call(host string, port int) {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatal("Resolving failed", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatal("UDP call failed", err)
	}
	response, err := SendBindingRequest(conn, addr)
	if err != nil {
		log.Fatal("Request failed", err)
	}
	if response.Header.IsValid() == false {
		log.Fatal(response)
	}
    for _, attr := range response.Attributes {
        if mapped, ok := attr.(*MappedAddress); ok {
            var family string
            switch mapped.Family {
            case 1:
                family = "IPv4"
            case 2:
                family = "IPv6"
            }

            fmt.Printf("%s %s %d\n", family, mapped.IP, mapped.Port)
        }
    }
}

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
