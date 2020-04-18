package tls

type CipherSuite uint16

const (
	Grease                                        CipherSuite = 0xbaba
	TLS_AES_128_GCM_SHA256                        CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384                        CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256                  CipherSuite = 0x1303
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         CipherSuite = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         CipherSuite = 0xc030
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuite = 0xcca8
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            CipherSuite = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            CipherSuite = 0xc014
	TLS_RSA_WITH_AES_128_GCM_SHA256               CipherSuite = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               CipherSuite = 0x009d
	TLS_RSA_WITH_AES_128_CBC_SHA                  CipherSuite = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  CipherSuite = 0x0035
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 CipherSuite = 0x000a
)
