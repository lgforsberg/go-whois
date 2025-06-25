package domain

import (
	"errors"
	"strings"
)

var AUMap map[string]string = map[string]string{
	"Registrant Contact Name": "c/registrant/name",
	"Registrant":              "c/registrant/organization",
	"Tech Contact Name":       "c/tech/name",
}

// AUParser represents a parser for AU domain whois responses.
// Deprecated: Use AUTLDParser instead.
type AUParser struct{}

// AUTLDParser is a specialized parser for .au domain whois responses.
// It handles the specific format used by .au ccTLD registry.
type AUTLDParser struct {
	parser IParser
}

// NewAUTLDParser creates a new parser for .au domain whois responses.
// The parser is configured to handle Australian registry field layouts.
func NewAUTLDParser() *AUTLDParser {
	return &AUTLDParser{
		parser: NewParser(),
	}
}

func (auw *AUTLDParser) GetName() string {
	return "au"
}

func (auw *AUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if rawtext == "" {
		return nil, errors.New("empty rawtext provided")
	}

	parsedWhois, err := auw.parser.Do(rawtext, nil, AUMap)
	if err != nil {
		return nil, err
	}

	// Validate that we have some meaningful data
	if parsedWhois.DomainName == "" && len(parsedWhois.Statuses) == 0 {
		// Check if this might be a "not found" response
		if strings.Contains(strings.ToLower(rawtext), "no data found") ||
			strings.Contains(strings.ToLower(rawtext), "not found") {
			SetDomainAvailabilityStatus(parsedWhois, true)
		}
	}

	return parsedWhois, nil
}
