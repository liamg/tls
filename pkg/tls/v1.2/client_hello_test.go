package v1_2

import (
	"fmt"
	"testing"
	"time"

	"github.com/liamg/tls/pkg/tls/generic"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestClientHelloEncodingAndDecoding(t *testing.T) {

	tests := []struct {
		sessionId        []byte
		supportedCiphers []generic.CipherSuite
		time             time.Time
		random           [28]byte
		extensions       []generic.Extension
		encoded          []byte
	}{
		{
			sessionId: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			supportedCiphers: []generic.CipherSuite{
				generic.TLS_AES_128_GCM_SHA256,
			},
			time: time.Unix(1234567890, 0),
			random: [28]byte{
				0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
				0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
			},
			extensions: []generic.Extension{
				generic.NewServerNameExtension([]generic.ServerName{
					{
						Type: generic.ServerNameTypeHostname,
						Name: "google.com",
					},
				}),
			},
			encoded: []byte{
				0x3, 0x3, // version
				0x49, 0x96, 0x2, 0xd2, // timestamp
				0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, // random
				0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, // ...
				0x10,                                                                                           // session id length
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // session id
				0x00, 0x02, //cipher suites length
				0x13, 0x01, // aes 128 gcm sha256
				0x01,       // compression method length
				0x00,       // compression method: none,
				0x00, 0x0f, // extensions length
				0x00, 0x0d, // client cert url extension
				0x00, 0x00, // extension data length
				0x01, 0x02, 0x03, // extension data
			},
		},
	}

	//

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			hello, err := NewClientHello(test.supportedCiphers, test.time, test.sessionId, test.extensions)
			require.NoError(t, err)

			hello.Random = test.random

			data, err := hello.Encode()
			require.NoError(t, err)

			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var hello ClientHello
			err := hello.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, generic.VersionTLS1_2, hello.Version)
			assert.Equal(t, test.time, hello.Timestamp)
			assert.Equal(t, test.random, hello.Random)
			assert.Equal(t, test.sessionId, hello.SessionId)
			assert.Equal(t, test.supportedCiphers, hello.SupportedCipherSuites)
			assert.Equal(t, test.extensions, hello.Extensions)
		})
	}

}
