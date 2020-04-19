package tls

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/liamg/tls/pkg/tls/generic"

	v1_2 "github.com/liamg/tls/pkg/tls/v1.2"
)

var ErrAlreadyConnected = fmt.Errorf("connection is already open")
var ErrAlreadyClosed = fmt.Errorf("connection is already closed")

var DefaultCipherSuites = []generic.CipherSuite{
	generic.TLS_AES_128_GCM_SHA256,
}

type Connection struct {
	host         string
	port         int
	timeout      time.Duration
	tcpConn      net.Conn
	tcpMutex     sync.Mutex
	isOpen       bool
	version      generic.Version
	cipherSuites []generic.CipherSuite
	sessionID    []byte
}

type Option func(conn *Connection)

func WithPort(port int) Option {
	return func(conn *Connection) {
		conn.port = port
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(conn *Connection) {
		conn.timeout = timeout
	}
}

func NewConnection(host string, options ...Option) (*Connection, error) {

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}

	conn := &Connection{
		host:         host,
		port:         4483,
		timeout:      time.Second * 10,
		version:      generic.VersionTLS1_3,
		cipherSuites: DefaultCipherSuites,
		sessionID:    sessionID,
	}

	for _, option := range options {
		option(conn)
	}

	return conn, nil
}

func (conn *Connection) Open() error {

	conn.tcpMutex.Lock()
	defer conn.tcpMutex.Unlock()

	if conn.isOpen {
		return ErrAlreadyConnected
	}

	tcpConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", conn.host, conn.port), conn.timeout)
	if err != nil {
		return err
	}

	if err := conn.handshake(tcpConn); err != nil {
		return err
	}

	conn.tcpConn = tcpConn

	conn.isOpen = true

	return nil
}

func (conn *Connection) Close() error {

	conn.tcpMutex.Lock()
	defer conn.tcpMutex.Unlock()

	if !conn.isOpen {
		return ErrAlreadyClosed
	}

	if err := conn.tcpConn.Close(); err != nil {
		return err
	}

	conn.isOpen = false
	conn.tcpConn = nil

	return nil
}

func (conn *Connection) Write(data []byte) (int, error) {
	return conn.tcpConn.Write(data)
}

func (conn *Connection) Read(data []byte) (int, error) {
	return conn.tcpConn.Read(data)
}

func (conn *Connection) handshake(tcpConn net.Conn) error {
	// Client sends supported ciphers, random number, session id and ServerNameIndication
	// Say Hi, then respond with chosen ciphers, random number, session id and ServerNameIndication

	if err := conn.sendClientHello(); err != nil {
		return err
	}

	return nil
}

func (conn *Connection) sendClientHello() error {

	clientHello, err := v1_2.NewClientHello(
		conn.cipherSuites,
		time.Now(),
		conn.sessionID,
		nil,
	)

	if err != nil {
		return err
	}

	clientHelloEncoded, err := clientHello.Encode()
	if err != nil {
		return err
	}

	clientHelloHandshake := generic.NewHandshake(generic.HandshakeTypeClientHello, clientHelloEncoded)
	clientHelloHandshakeEncoded, err := clientHelloHandshake.Encode()
	if err != nil {
		return err
	}

	record := generic.NewRecord(
		generic.ContentTypeHandshake,
		conn.version,
		clientHelloHandshakeEncoded,
	)

	data, err := record.Encode()
	if err != nil {
		return err
	}

	var total int
	for total < len(data) {
		size, err := conn.tcpConn.Write(data[total:])
		if err != nil {
			return err
		}
		total += size
	}

	return nil
}
