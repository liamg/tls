package generic

import (
	"fmt"
	"testing"

	"github.com/liamg/tls/pkg/tls/generic"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestSupportedGroupsExtensionEncodingAndDecoding(t *testing.T) {

	tests := []struct {
		supportedGroups []generic.SupportedGroup
		encoded         []byte
	}{
		{
			supportedGroups: []generic.SupportedGroup{
				generic.SECP256R1,
				generic.SECP384R1,
				generic.X25519,
				generic.X448,
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

			supportedGroupsExtension := generic.NewSupportedGroupsExtension(test.supportedGroups)

			data, err := supportedGroupsExtension.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var supportedGroupsExtension generic.SupportedGroupsExtension
			err := supportedGroupsExtension.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.supportedGroups, supportedGroupsExtension.SupportedGroups)
		})
	}

}
