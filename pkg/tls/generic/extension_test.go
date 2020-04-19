package generic

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionPackingAndUnpacking(t *testing.T) {

	tests := []struct {
		extension Extension
		packed    []byte
	}{
		{
			extension: NewServerNameExtension([]ServerName{
				{
					Name: "google.com",
					Type: ServerNameTypeHostname,
				},
			}),
			packed: []byte{
				0x0, 0x0, // type
				0x0, 0xf, // size
				0x0, 0xd, 0x0, 0x0, 0xa, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // ext data
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Pack #%d", i), func(t *testing.T) {
			data, err := PackExtension(test.extension)
			require.NoError(t, err)
			assert.Equal(t, test.packed, data)
		})
		t.Run(fmt.Sprintf("Unpack #%d", i), func(t *testing.T) {
			reader := bytes.NewReader(test.packed)
			extension, err := UnpackExtension(reader)
			require.NoError(t, err)
			assert.Equal(t, test.extension, extension)
		})
	}

}
