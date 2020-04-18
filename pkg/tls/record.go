package tls

import "fmt"

// See https://tools.ietf.org/html/rfc5246#section-6.2.1

type Record struct {
	ContentType ContentType
	Version     Version
	Fragment    []byte
}

func NewRecord(contentType ContentType, version Version, fragment []byte) *Record {
	return &Record{
		ContentType: contentType,
		Version:     version,
		Fragment:    fragment,
	}
}

func (r *Record) Decode(data []byte) error {

	if len(data) < 5 {
		return fmt.Errorf("invalid TLS Record record - length should be >= 5 bytes, was %d", len(data))
	}

	r.ContentType = ContentType(data[0])
	r.Version = Version((uint16(data[1]) << 8) + uint16(data[2]))

	fragmentLength := (uint16(data[3]) << 8) + uint16(data[4])

	if len(data) != int(fragmentLength)+5 {
		return fmt.Errorf("invalid TLS Record record - fragment length declared as %d, was %d", fragmentLength, len(data)-5)
	}

	r.Fragment = data[5:]

	return nil
}

func (r *Record) Encode() ([]byte, error) {

	length := uint16(len(r.Fragment))

	output := make([]byte, int(length)+5)

	output[0] = byte(r.ContentType)
	output[1] = byte(r.Version >> 8)
	output[2] = byte(r.Version & 0xff)
	output[3] = byte(length >> 8)
	output[4] = byte(length & 0xff)

	for i, b := range r.Fragment {
		output[i+5] = b
	}

	return output, nil
}
