package domain

import (
	"strings"
)

type BGParser struct{}

type BGTLDParser struct {
	parser IParser
}

func NewBGTLDParser() *BGTLDParser {
	return &BGTLDParser{
		parser: NewParser(),
	}
}

func (bgw *BGTLDParser) GetName() string {
	return "bg"
}

func (bgw *BGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found (empty response)
	if strings.TrimSpace(rawtext) == "" {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var inNameserversSection bool

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "DOMAIN NAME:") {
			// Extract domain name from "DOMAIN NAME: google.bg (google.bg)" format
			domainPart := strings.TrimPrefix(line, "DOMAIN NAME:")
			if idx := strings.Index(domainPart, "("); idx != -1 {
				parsedWhois.DomainName = strings.TrimSpace(domainPart[:idx])
			} else {
				parsedWhois.DomainName = strings.TrimSpace(domainPart)
			}
		} else if strings.HasPrefix(line, "registration status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "registration status:"))
			// Parse status like "busy, active" - extract the main status
			if strings.Contains(status, "active") {
				parsedWhois.Statuses = []string{"active"}
			} else if strings.Contains(status, "busy") {
				parsedWhois.Statuses = []string{"busy"}
			} else {
				parsedWhois.Statuses = []string{status}
			}
		} else if line == "NAME SERVER INFORMATION:" {
			inNameserversSection = true
		} else if inNameserversSection && line != "" && !strings.HasPrefix(line, "DNSSEC:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, line)
		} else if strings.HasPrefix(line, "DNSSEC:") {
			inNameserversSection = false
		}
	}

	return parsedWhois, nil
}
