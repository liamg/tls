package generic

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestHandshakeEncodingAndDecoding(t *testing.T) {

	random := make([]byte, 0xffffff)
	_, err := rand.Read(random)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		hsType  HandshakeType
		body    []byte
		encoded []byte
	}{
		{
			hsType:  HandshakeTypeClientHello,
			body:    []byte{1, 2, 3},
			encoded: []byte{0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			hsType:  HandshakeTypeClientKeyExchange,
			body:    []byte{},
			encoded: []byte{0x10, 0x00, 0x00, 0x00},
		},
		{
			hsType:  HandshakeTypeServerHello,
			body:    random,
			encoded: append([]byte{0x02, 0xff, 0xff, 0xff}, random...),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			handshake := NewHandshake(
				test.hsType,
				test.body,
			)

			data, err := handshake.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var handshake Handshake
			err := handshake.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.hsType, handshake.Type)
			assert.Equal(t, test.body, handshake.Data)
		})
	}

}
