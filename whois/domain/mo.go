package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type MOTLDParser struct {
	parser IParser
}

func NewMOTLDParser() *MOTLDParser {
	return &MOTLDParser{
		parser: NewParser(),
	}
}

func (mow *MOTLDParser) GetName() string {
	return "mo"
}

func (mow *MOTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "No match for") {
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	var inNameservers bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Record created on") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Record created on"))
		} else if strings.HasPrefix(line, "Record expires on") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Record expires on"))
		} else if strings.HasPrefix(line, "Domain name servers:") {
			inNameservers = true
			continue
		} else if inNameservers {
			if strings.HasPrefix(line, "-") { // separator line
				continue
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, line)
		}
	}

	return parsedWhois, nil
}
