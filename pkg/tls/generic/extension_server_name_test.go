package generic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestServerNameExtensionEncodingAndDecoding(t *testing.T) {

	tests := []struct {
		names   []ServerName
		encoded []byte
	}{
		{
			names: []ServerName{
				{
					Type: ServerNameTypeHostname,
					Name: "id.google.com",
				},
			},
			encoded: []byte{
				0x00, 0x10, 0x00, 0x00, 0x0d, 0x69, 0x64, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
				0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			serverNameExtension := NewServerNameExtension(test.names)

			data, err := serverNameExtension.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var serverNameExtension ServerNameExtension
			err := serverNameExtension.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.names, serverNameExtension.ServerNames)
		})
	}

}
