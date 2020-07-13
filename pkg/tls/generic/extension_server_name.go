package generic

import "fmt"

type ServerNameType byte

const (
	ServerNameTypeHostname ServerNameType = 0
)

type ServerName struct {
	Type ServerNameType
	Name string
}

type ServerNameExtension struct {
	ServerNames []ServerName
}

func NewServerNameExtension(serverNames []ServerName) *ServerNameExtension {
	return &ServerNameExtension{
		ServerNames: serverNames,
	}
}

func (e *ServerNameExtension) GetType() ExtensionType {
	return ExtensionTypeServerName
}

func (e *ServerNameExtension) Encode() ([]byte, error) {
	var output []byte

	output = append(output, 0, 0)

	for _, name := range e.ServerNames {
		output = append(output,
			byte(name.Type),
			byte(len(name.Name)>>8),
			byte(len(name.Name)&0xff),
		)
		output = append(output, []byte(name.Name)...)
	}

	length := len(output) - 2

	output[0] = byte(length >> 8)
	output[1] = byte(length & 0xff)

	return output, nil
}

func (e *ServerNameExtension) Decode(data []byte) error {
	length := (uint16(data[0]) << 8) + uint16(data[1])&0xff
	if len(data) != int(length)+2 {
		return fmt.Errorf("invalid server name extension length")
	}

	index := 2
	var readCount uint16
	for readCount < length {
		var name ServerName
		name.Type = ServerNameType(data[index])
		index++
		nameLength := (uint16(data[index]) << 8) + uint16(data[index+1])&0xff
		index += 2
		name.Name = string(data[index : index+int(nameLength)])
		e.ServerNames = append(e.ServerNames, name)
		index += int(nameLength)
		readCount += nameLength + 3
	}

	return nil
}
