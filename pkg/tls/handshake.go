package tls

import "fmt"

type HandshakeType uint8

const (
	HandshakeTypeHelloRequest       HandshakeType = 0x00
	HandshakeTypeClientHello        HandshakeType = 0x01
	HandshakeTypeServerHello        HandshakeType = 0x02
	HandshakeTypeCertificate        HandshakeType = 0x0b
	HandshakeTypeServerKeyExchange  HandshakeType = 0x0c
	HandshakeTypeCertificateRequest HandshakeType = 0xd
	HandshakeTypeServerHelloDone    HandshakeType = 0xe
	HandshakeTypeCertificateVerify  HandshakeType = 0xf
	HandshakeTypeClientKeyExchange  HandshakeType = 0x10
	HandshakeTypeFinished           HandshakeType = 0x14
)

type Handshake struct {
	Type HandshakeType
	Body []byte
}

func NewHandshake(handshakeType HandshakeType, body []byte) Handshake {
	return Handshake{
		Type: handshakeType,
		Body: body,
	}
}

func (h *Handshake) Encode() ([]byte, error) {

	output := make([]byte, 4+len(h.Body))

	// type
	output[0] = byte(h.Type)

	// length
	length := len(h.Body)
	output[1] = byte(length >> 16)
	output[2] = byte((length & 0xff00) >> 8)
	output[3] = byte(length & 0xff)

	// body
	for i, b := range h.Body {
		output[i+4] = b
	}

	return output, nil
}

func (h *Handshake) Decode(data []byte) error {

	if len(data) < 4 {
		return fmt.Errorf("invalid handshake length, expected >=4, got %d", len(data))
	}

	h.Type = HandshakeType(data[0])

	length := (uint64(data[1]) << 16) + (uint64(data[2]) << 8) + uint64(data[3])

	if len(data) != int(length+4) {
		return fmt.Errorf("invalid handshake payload, expected %d, got %d", length, len(data)-4)
	}

	h.Body = data[4:]

	return nil
}
