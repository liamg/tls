package v1_2

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/liamg/tls/pkg/tls/generic"
)

type ClientHello struct {
	Version               generic.Version
	Timestamp             time.Time
	Random                [28]byte
	SessionId             []byte
	SupportedCipherSuites []generic.CipherSuite
	CompressionMethods    []generic.CompressionMethod
	Extensions            []generic.Extension
}

func NewClientHello(supportedCiphers []generic.CipherSuite, timestamp time.Time, sessionID []byte, extensions []generic.Extension) (*ClientHello, error) {

	hello := &ClientHello{
		Version:               generic.VersionTLS1_2,
		Timestamp:             timestamp,
		SessionId:             sessionID,
		SupportedCipherSuites: supportedCiphers,
		CompressionMethods: []generic.CompressionMethod{
			generic.CompressionMethodNone,
		},
		Extensions: extensions,
	}

	random := make([]byte, 28)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	copy(hello.Random[:], random)

	return hello, nil
}

func (c *ClientHello) Encode() ([]byte, error) {

	output := make([]byte, 0, 0xffff)

	// version
	output = append(output, byte(c.Version>>8), byte(c.Version&0xff))

	// timestamp
	unixTimestamp := uint32(c.Timestamp.Unix())
	output = append(
		output,
		byte(unixTimestamp>>24),
		byte((unixTimestamp>>16)&0xff),
		byte((unixTimestamp>>8)&0xff),
		byte(unixTimestamp&0xff),
	)

	// random
	output = append(output, c.Random[:]...)

	// session id
	if len(c.SessionId) > 0xff {
		return nil, fmt.Errorf("session id should be 255 bytes maximum - was %d", len(c.SessionId))
	}
	output = append(output, byte(len(c.SessionId)&0xff))
	output = append(output, c.SessionId[:]...)

	// supported cipher suites
	suiteLength := len(c.SupportedCipherSuites) * 2
	if suiteLength > 0xffff {
		return nil, fmt.Errorf("length of supported cipher suites should be %d bytes maximum - was %d", 0xffff, suiteLength)
	}
	output = append(output, byte(suiteLength>>8), byte(suiteLength&0xff))
	for _, suite := range c.SupportedCipherSuites {
		output = append(output, byte(suite>>8), byte(suite&0xff))
	}

	// compression methods
	compressionMethodCount := len(c.CompressionMethods)
	if compressionMethodCount > 0xff {
		return nil, fmt.Errorf("number of compression methods should be %d maximum - was %d", 0xff, compressionMethodCount)
	}
	output = append(output, byte(compressionMethodCount))
	for _, method := range c.CompressionMethods {
		output = append(output, byte(method))
	}

	// extensions
	extensionLengthIndex := len(output)
	output = append(output, 0, 0)
	var extensionLength int
	for _, extension := range c.Extensions {
		extData, err := generic.PackExtension(extension)
		if err != nil {
			return nil, fmt.Errorf("failed to encode extension: %s", err)
		}
		output = append(output, extData...)
		extensionLength += len(extData)
	}

	if extensionLength > 0xffff {
		return nil, fmt.Errorf("length of supported extensions should be %d bytes maximum - was %d", 0xffff, extensionLength)
	}
	output[extensionLengthIndex] = byte(extensionLength >> 8)
	output[extensionLengthIndex+1] = byte(extensionLength & 0xff)

	return output, nil
}

func (c *ClientHello) Decode(data []byte) error {

	if len(data) < 35 {
		return fmt.Errorf("invalid length for client hellp: %d", len(data))
	}

	c.Version = generic.Version((uint16(data[0]) << 8) + uint16(data[1]))

	timestamp := (uint32(data[2]) << 24) + (uint32(data[3]) << 16) + (uint32(data[4]) << 8) + (uint32(data[5]))
	c.Timestamp = time.Unix(int64(timestamp), 0)

	copy(c.Random[:], data[6:34])

	sessionIdLength := data[34]

	c.SessionId = data[35 : 35+sessionIdLength]

	index := 35 + int(sessionIdLength)
	cypherSuiteLength := (uint16(data[index]) << 8) + uint16(data[index+1])
	index += 2

	for i := 0; i < int(cypherSuiteLength); i += 2 {
		c.SupportedCipherSuites = append(
			c.SupportedCipherSuites,
			generic.CipherSuite((uint16(data[index])<<8)+uint16(data[index+1])),
		)
		index += 2
	}

	compressionMethodsLength := data[index]
	index++

	for i := 0; i < int(compressionMethodsLength); i++ {
		c.CompressionMethods = append(c.CompressionMethods, generic.CompressionMethod(data[index]))
		index++
	}

	extensionLength := (uint16(data[index]) << 8) + uint16(data[index+1])
	index += 2

	var extensionByteCount uint16

	for extensionByteCount < extensionLength {
		var extension generic.Extension
		extensionType := generic.ExtensionType((uint16(data[index]) << 8) + uint16(data[index+1]))
		index += 2
		length := (uint16(data[index]) << 8) + uint16(data[index+1])
		index += 2
		extensionData := data[index : index+int(length)]
		extension, err := generic.ParseExtension(extensionType, extensionData)
		if err != nil {
			return err
		}
		c.Extensions = append(c.Extensions, extension)
		extensionByteCount += 4 + length
		index += int(length)
	}

	return nil
}
