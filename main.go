package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

var (
	unrecognizedAddrType = errors.New("Unrecognized address type")
)

const (
	socks5Version = uint8(5)
)

const (
	SockAddr_IPV4 = 0x01
	SockAddr_FQDN = 0x03
	SockAddr_IPV6 = 0x04
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if len(a.IP) != 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}
	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	switch addrType[0] {
	case SockAddr_IPV4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, 4); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case SockAddr_FQDN:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	case SockAddr_IPV6:
		panic("IPv6 not implemented.")

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	destPort := binary.BigEndian.Uint16(port)
	d.Port = int(destPort)
	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

func handleClient(clientConn net.Conn) error {
	defer clientConn.Close()

	bufConn := bufio.NewReader(clientConn)
	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		fmt.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}
	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("unsupported SOCKS version: %v", version)
		fmt.Printf("[ERR] socks: %v", err)
		return err
	}

	auth := []byte{0x0}
	if _, err := bufConn.Read(auth); err != nil {
		fmt.Printf("[ERR] socks: Failed to get auth len: %v", err)
		return err
	}
	authLen := int(auth[0])
	fqdn := make([]byte, authLen)
	if _, err := io.ReadAtLeast(bufConn, fqdn, authLen); err != nil {
		return fmt.Errorf("[ERR] socks: Failed to get auth params: %v", err)
	}

	// send reaponse to client ===> version, method
	if _, err := clientConn.Write([]byte{0x05, 0x0}); err != nil {
		fmt.Printf("[ERR] socket: Failed to write: %v", err)
		return err
	}

	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return fmt.Errorf("failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported command version: %v", header[0])
	}

	// Only CONNECT command supported
	if header[1] != 0x01 {
		return fmt.Errorf("unsupported command: %v", header[0])
	}

	// get IP or FQDN
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		fmt.Println("Can not parse socks5 header.")
		return fmt.Errorf("can not parse socks5 header: %v", header[0])
	}

	if dest.FQDN != "" {
		addr, err := net.ResolveIPAddr("ip", dest.FQDN)
		if err != nil {
			if err := sendReply(clientConn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
			return fmt.Errorf("failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		dest.IP = addr.IP
	}

	// connect to taget host
	targetHost, err := net.Dial("tcp", dest.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(clientConn, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %v", targetHost.RemoteAddr().String(), err)
	}
	defer targetHost.Close()

	// Send success
	local := targetHost.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(clientConn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start proxying
	errCh1 := make(chan error, 1)
	errCh2 := make(chan error, 1)
	go proxy(targetHost, bufConn, errCh1)
	go proxy(clientConn, targetHost, errCh2)

	// Wait
	select {
	case e1 := <-errCh1:
		if e1 != nil {
			// return from this function closes target (and conn).
			return e1
		}
	case e2 := <-errCh2:
		if e2 != nil {
			// return from this function closes target (and conn).
			return e2
		}
	}

	return nil
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		fmt.Println("Failed to listen.")
		return
	}
	fmt.Println("Listening on port 1080.")

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept a new connection.")
			continue
		}
		fmt.Printf("New connection: %v\n", conn.RemoteAddr().String())
		go handleClient(conn)
	}
}
