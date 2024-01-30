# simple-socks5
Simple sokcks5 server in Go<br>

:warning: **It is not a fully implemented SOCKS5 proxy; rather, it is intended solely for educational purposes.**

Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)

<p align="center">
  <img src="images/Diagram.png?raw=true" width="450" title="hover text">
</p>

## Create a new socket

First, we need to create a new socket and listen on it. Then, in a loop, we accept clients and handle them in goroutines.

<details>
  <summary>Code</summary>

```go
func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:1080")
	// ...

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		// ...
		go handleClient(conn)
	}
}
```
</details>

## Stage A
The format of the first message is as follows: the client specifies the SOCKS version, which in this case is 0x05, and the NMETHODS field contains the number of method identifier octets that appear in the METHODS field.


<br>

```
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
```

<details>
  <summary>Code</summary>

```go
	// ...

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

	// ...
```
</details>

## Stage B
The server selects one of the methods given in METHODS and sends a METHOD selection message. In this server app, we only implemented X'00' NO AUTHENTICATION REQUIRED.
```
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
```

<details>
  <summary>Code</summary>

```go
	// ...
	if _, err := clientConn.Write([]byte{0x05, 0x0}); err != nil {
		fmt.Printf("[ERR] socket: Failed to write: %v", err)
		return err
	}
	// ...
```
</details>


## Stage C
There are three options for the ATYPE field. If the client has chosen DOMAINNAME, we should resolve the name to an IP address. <br>
&nbsp;&nbsp;&nbsp;&nbsp;o  IP V4 address: X'01' <br>
&nbsp;&nbsp;&nbsp;&nbsp;o  DOMAINNAME: X'03' <br>
&nbsp;&nbsp;&nbsp;&nbsp;o  IP V6 address: X'04' <br>
```
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```

<details>
  <summary>Code</summary>

```go
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
			// ..
		}
		dest.IP = addr.IP
	}
	// ...
```
</details>

## Connect to target host
If everything up to this point is correct, we attempt to connect to the host using the information provided by the client.

<details>
  <summary>Code</summary>

```go
	// ...
	targetHost, err := net.Dial("tcp", dest.Address())
	if err != nil {
		// ..
	}
	defer targetHost.Close()
	// ...
```
</details>

## Stage D

<details>
  <summary>Code</summary>

```go
	// ...
	local := targetHost.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(clientConn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	// ...
```
</details>

# Proxy data
In the last step, we create two goroutines to forward the client's data to the server and forward the response from the server to the client.

<details>
  <summary>Code</summary>

```go
	// ...
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
	// ...
```
</details>