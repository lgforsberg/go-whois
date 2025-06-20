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

type AUParser struct{}

type AUTLDParser struct {
	parser IParser
}

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
			parsedWhois.Statuses = []string{"free"}
		}
	}

	return parsedWhois, nil
}
