package domain

import (
	"regexp"
	"strings"
)

// UZTLDParser represents the parser for .uz TLD
type UZTLDParser struct {
	parser IParser
}

// NewUZTLDParser creates a new UZTLDParser
func NewUZTLDParser() *UZTLDParser {
	return &UZTLDParser{
		parser: NewParser(),
	}
}

// GetName returns the name of the parser
func (p *UZTLDParser) GetName() string {
	return "uz"
}

// GetParsedWhois parses the whois response for .uz domains
func (p *UZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "not found in database") {
		parsedWhois := &ParsedWhois{
			DomainName: extractDomainFromNotFound(rawtext),
		}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	// Use default parser with custom key mappings
	keyMap := map[string]string{
		"Domain Name:":     "domain_name",
		"Registrar:":       "registrar",
		"Name Server:":     "name_servers",
		"Status:":          "statuses",
		"Updated Date:":    "updated_date",
		"Creation Date:":   "created_date",
		"Expiration Date:": "expired_date",
	}

	parsed, err := p.parser.Do(rawtext, func(line string) bool {
		return strings.HasPrefix(line, ">>>") || strings.HasPrefix(line, "% >>>")
	}, keyMap)

	if err != nil {
		return nil, err
	}

	// Clean up nameservers by removing "<no value>" part
	if parsed.NameServers != nil {
		cleanedNS := make([]string, 0, len(parsed.NameServers))
		for _, ns := range parsed.NameServers {
			// Remove "<no value>" part if present
			if strings.Contains(ns, "<no value>") {
				ns = strings.TrimSpace(strings.Split(ns, "<no value>")[0])
			}
			if ns != "" {
				cleanedNS = append(cleanedNS, ns)
			}
		}
		parsed.NameServers = cleanedNS
	}

	return parsed, nil
}

// extractDomainFromNotFound extracts domain name from "not found" message
func extractDomainFromNotFound(rawtext string) string {
	re := regexp.MustCompile(`domain:\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(rawtext)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
