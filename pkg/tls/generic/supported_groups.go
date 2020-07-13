package generic

type SupportedGroup uint16

// have just included the recommended groups for now. There are many others: (https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
const (
	SECP256R1 SupportedGroup = 0x0017
	SECP384R1 SupportedGroup = 0x0018
	X25519    SupportedGroup = 0x0023
	X448      SupportedGroup = 0x0024
)
