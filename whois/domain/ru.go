package domain

var RUMap map[string]string = map[string]string{
	"admin-contact": "reg/url",
	"state":         "statuses",
	"org":           "c/registrant/organization",
}

// RUParser represents a parser for RU domain whois responses.
// Deprecated: Use RUTLDParser instead.
type RUParser struct{}

// RUTLDParser is a specialized parser for .ru domain whois responses.
// It handles the specific format used by the Russian registry.
type RUTLDParser struct {
	parser IParser
}

// NewRUTLDParser creates a new parser for .ru domain whois responses.
// The parser is configured to handle Russian registry field layouts.
func NewRUTLDParser() *RUTLDParser {
	return &RUTLDParser{
		parser: NewParser(),
	}
}

func (ruw *RUTLDParser) GetName() string {
	return "ru"
}

func (ruw *RUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := ruw.parser.Do(rawtext, nil, RUMap)
	if err != nil {
		return nil, err
	}
	return parsedWhois, nil
}
