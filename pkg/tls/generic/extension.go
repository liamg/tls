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
