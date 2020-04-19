package generic

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestRecordEncodingAndDecoding(t *testing.T) {

	random := make([]byte, 0xffff)
	_, err := rand.Read(random)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		contentType ContentType
		version     Version
		fragment    []byte
		encoded     []byte
	}{
		{
			contentType: ContentTypeHandshake,
			version:     VersionTLS1_3,
			fragment:    []byte{9, 8, 7, 6},
			encoded:     []byte{0x16, 0x03, 0x04, 0x00, 0x04, 0x09, 0x08, 0x07, 0x06},
		},
		{
			contentType: ContentTypeAlert,
			version:     VersionTLS1_1,
			fragment:    []byte{},
			encoded:     []byte{0x15, 0x03, 0x02, 0x00, 0x00},
		},
		{
			contentType: ContentTypeApplicationData,
			version:     VersionTLS1_0,
			fragment:    []byte{0, 0},
			encoded:     []byte{0x17, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00},
		},
		{
			contentType: ContentTypeChangeCipherSpec,
			version:     VersionTLS1_2,
			fragment:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			encoded:     []byte{0x14, 0x03, 0x03, 0x00, 0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			contentType: ContentTypeHeartbeat,
			version:     Version(0x1234),
			fragment:    random,
			encoded: append(
				[]byte{0x18, 0x12, 0x34, 0xff, 0xff},
				random...,
			),
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("Encode #%d", i), func(t *testing.T) {

			record := NewRecord(
				test.contentType,
				test.version,
				test.fragment,
			)

			data, err := record.Encode()
			require.NoError(t, err)
			assert.Equal(t, test.encoded, data)
		})

		t.Run(fmt.Sprintf("Decode #%d", i), func(t *testing.T) {

			var record Record
			err := record.Decode(test.encoded)
			require.NoError(t, err)

			assert.Equal(t, test.contentType, record.ContentType)
			assert.Equal(t, test.version, record.Version)
			assert.Equal(t, test.fragment, record.Fragment)
		})
	}

}
