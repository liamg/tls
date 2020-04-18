package tls

type ClientHello struct {
	ProtocolVersion      Version
	Random               []byte
	SessionId            []byte
	SupportedCiphers     []CipherSuite
	ServerNameIndication string
}

func NewClientHello(supportedCiphers []CipherSuite, serverNameIndication string, random []byte, sessionID []byte) (*ClientHello, error) {
	return &ClientHello{
		ProtocolVersion:      VersionTLS1_2,
		Random:               random,
		SessionId:            sessionID,
		SupportedCiphers:     supportedCiphers,
		ServerNameIndication: serverNameIndication,
	}, nil
}

func (c *ClientHello) Encode() ([]byte, error) {
	return nil, nil
}

func (c *ClientHello) Decode(data []byte) error {
	return nil
}
