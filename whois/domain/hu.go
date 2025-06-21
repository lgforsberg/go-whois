package domain

import (
	"errors"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type HUTLDParser struct {
	parser IParser
}

func NewHUTLDParser() *HUTLDParser {
	return &HUTLDParser{
		parser: NewParser(),
	}
}

func (huw *HUTLDParser) GetName() string {
	return "hu"
}

func (huw *HUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if rawtext == "" {
		return nil, errors.New("empty rawtext provided")
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "Korlatozott domain nev") || strings.Contains(rawtext, "Restricted domain name") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if strings.HasPrefix(line, "domain:") {
			domainName := utils.ExtractField(line, "domain:")
			if domainName != "" {
				parsedWhois.DomainName = domainName
			}
		} else if strings.HasPrefix(line, "record created:") {
			createdDate := utils.ExtractField(line, "record created:")
			if createdDate != "" {
				parsedWhois.CreatedDateRaw = createdDate
			}
		}
	}

	if parsedWhois.DomainName != "" {
		parsedWhois.Statuses = []string{"Active"}
	}

	// Convert date format with error handling
	if parsedWhois.CreatedDateRaw != "" {
		convertedDate, err := utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
		if err != nil {
			// Log the error but don't fail the entire parsing
			// The raw date is still available in CreatedDateRaw
		} else {
			parsedWhois.CreatedDate = convertedDate
		}
	}

	return parsedWhois, nil
}
