package generic

import "fmt"

type SupportedGroupsExtension struct {
	SupportedGroupsListLength byte
	SupportedGroups           []SupportedGroup
}

func NewSupportedGroupsExtension(supportedGroups []SupportedGroup) *SupportedGroupsExtension {
	return &SupportedGroupsExtension{
		SupportedGroupsListLength: byte(2 * len(supportedGroups)),
		SupportedGroups:           supportedGroups,
	}
}

func (e *SupportedGroupsExtension) GetType() ExtensionType {
	return ExtensionTypeSupportedGroups
}

func (e *SupportedGroupsExtension) Encode() ([]byte, error) {
	var output []byte

	output = append(output, 0, byte(e.SupportedGroupsListLength))

	for _, group := range e.SupportedGroups {
		output = append(output, 0, byte(group))
	}

	return output, nil
}

func (e *SupportedGroupsExtension) Decode(data []byte) error {
	length := (uint16(data[0]) + uint16(data[1]))
	if len(data) != int(length)+2 {
		return fmt.Errorf("Invalid supported groups extension length")
	}

	for i := 2; i < int(length)+2; i += 2 {
		var group SupportedGroup
		group = SupportedGroup(data[i] + data[i+1])
		e.SupportedGroups = append(e.SupportedGroups, group)
	}
	return nil
}
