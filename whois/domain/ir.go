package domain

var IRMap map[string]string = map[string]string{
	"expire-date":  "expired_date",
	"last-updated": "updated_date",
}

type IRParser struct{}

type IRTLDParser struct {
	parser IParser
}

func NewIRTLDParser() *IRTLDParser {
	return &IRTLDParser{
		parser: NewNicHdlParser(map[string]string{
			"e-mail":  "email",
			"org":     "organization",
			"address": "street",
			"fax-no":  "fax",
			"country": "country",
			"phone":   "phone",
		}),
	}
}

func (irw *IRTLDParser) GetName() string {
	return "ir"
}

func (irw *IRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := irw.parser.Do(rawtext, nil, IRMap)
	if err != nil {
		return nil, err
	}
	return parsedWhois, nil
}
