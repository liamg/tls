package generic

import "fmt"

type AlertLevel byte

const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
)

type AlertDescription byte

const (
	AlertUnexpectedMessage           AlertDescription = 10
	AlertBadRecordMAC                AlertDescription = 20
	AlertDecryptionFailed            AlertDescription = 21
	AlertRecordOverflow              AlertDescription = 22
	AlertDecompressionFailure        AlertDescription = 30
	AlertHandshakeFailure            AlertDescription = 40
	AlertNoCertificate               AlertDescription = 41
	AlertBadCertificate              AlertDescription = 42
	AlertUnsupportedCertificate      AlertDescription = 43
	AlertCertificateRevoked          AlertDescription = 44
	AlertCertificateExpired          AlertDescription = 45
	AlertCertificateUnknown          AlertDescription = 46
	AlertIllegalParameter            AlertDescription = 47
	AlertUnknownCertificateAuthority AlertDescription = 48
	AlertAccessDenied                AlertDescription = 49
	AlertDecodeError                 AlertDescription = 50
	AlertDecryptError                AlertDescription = 51
	AlertExportRestriction           AlertDescription = 60
	AlertProtocolVersion             AlertDescription = 70
	AlertInsufficientSecurity        AlertDescription = 71
	AlertInternalError               AlertDescription = 80
	AlertUserCancelled               AlertDescription = 90
	AlertNoRenegotiation             AlertDescription = 100
	AlertUnsupportedExtension        AlertDescription = 110
)

type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

func NewAlert(level AlertLevel, description AlertDescription) *Alert {
	return &Alert{
		Level:       level,
		Description: description,
	}
}

func (a *Alert) Encode() ([]byte, error) {
	return []byte{
		byte(a.Level),
		byte(a.Description),
	}, nil
}

func (a *Alert) Decode(data []byte) error {

	if len(data) != 2 {
		return fmt.Errorf("invalid alert length - expected 2, got %d", len(data))
	}

	a.Level = AlertLevel(data[0])
	a.Description = AlertDescription(data[1])
	return nil
}
