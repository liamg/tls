package generic

import "fmt"

type ExtensionType uint16

const (
	ExtensionTypeServerName           ExtensionType = 0
	ExtensionTypeMaxFragmentLength    ExtensionType = 1
	ExtensionTypeClientCertificateURL ExtensionType = 2
	ExtensionTypeTrustedCAKeys        ExtensionType = 3
	ExtensionTypeTruncatedHMAC        ExtensionType = 4
	ExtensionTypeStatusRequest        ExtensionType = 5
)

type Extension interface {
	GetType() ExtensionType
	Encoder
	Decoder
}

func ParseExtension(extensionType ExtensionType, data []byte) (Extension, error) {
	switch extensionType {
	case ExtensionTypeServerName:
		var serverNameExtension ServerNameExtension
		err := serverNameExtension.Decode(data)
		return &serverNameExtension, err
	default:
		return nil, fmt.Errorf("unknown extension type: %X", extensionType)
	}
}

func PackExtension(extension Extension) ([]byte, error) {
	var output []byte
	t := extension.GetType()

	output = append(output, byte(t>>8), byte(t&0xff))

	input, err := extension.Encode()
	if err != nil {
		return nil, err
	}

	if len(input) > 0xffff {
		return nil, fmt.Errorf("extension data exceeded max length of 0xffff")
	}

	output = append(output, byte(len(input)>>8), byte(len(input)&0xff))
	output = append(output, input...)
	return output, nil
}
