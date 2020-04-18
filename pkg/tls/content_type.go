package tls

type ContentType byte

const (
	ContentTypeChangeCipherSpec ContentType = 0x14
	ContentTypeAlert            ContentType = 0x15
	ContentTypeHandshake        ContentType = 0x16
	ContentTypeApplicationData  ContentType = 0x17
	ContentTypeHeartbeat        ContentType = 0x18
)
