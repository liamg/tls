package generic

type Version uint16

/*
	{3, 3} refers to TLS 1.2 - the value 3.3 is historical, deriving from the use of {3, 1} for TLS 1.0.
*/
const (
	VersionTLS1_0 Version = 0x0301
	VersionTLS1_1 Version = 0x0302
	VersionTLS1_2 Version = 0x0303
	VersionTLS1_3 Version = 0x0304
)
