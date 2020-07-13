package generic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestSupportedGroupsExtensionEncodingAndDecoding(t *testing.T) {

	tests := []struct {
		supportedGroups []SupportedGroup
		encoded         []byte
	}{
		{
			supportedGroups: []SupportedGroup{
				SECP256R1,
				SECP384R1,
				X25519,
				X448,
			},
			encoded: []byte{
				0x00, 0x8, // length
				0x00, 0x17, // secp256r1,
				0x00, 0x18, // secp384r1,
				0x00, 0x23, // x25519,
				0x00, 0x24, // x448,
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			supportedGroupsExtension := NewSupportedGroupsExtension(test.supportedGroups)

			data, err := supportedGroupsExtension.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var supportedGroupsExtension SupportedGroupsExtension
			err := supportedGroupsExtension.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.supportedGroups, supportedGroupsExtension.SupportedGroups)
		})
	}

}
