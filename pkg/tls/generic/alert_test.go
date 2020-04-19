package generic

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertEncodingAndDecoding(t *testing.T) {

	tests := []struct {
		level       AlertLevel
		description AlertDescription
		encoded     []byte
	}{
		{
			level:       AlertLevelWarning,
			description: AlertUnexpectedMessage,
			encoded:     []byte{0x1, 0x0a},
		},
		{
			level:       AlertLevelFatal,
			description: AlertAccessDenied,
			encoded:     []byte{0x2, 0x31},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			alert := NewAlert(
				test.level,
				test.description,
			)

			data, err := alert.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var alert Alert
			err := alert.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.level, alert.Level)
			assert.Equal(t, test.description, alert.Description)
		})
	}
}
