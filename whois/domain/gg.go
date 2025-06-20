package domain

import (
	"strings"
)

type GGTLDParser struct {
	parser IParser
}

func NewGGTLDParser() *GGTLDParser {
	return &GGTLDParser{
		parser: NewParser(),
	}
}

func (ggw *GGTLDParser) GetName() string {
	return "gg"
}

func (ggw *GGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if strings.Contains(rawtext, "NOT FOUND") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if sec := ggw.detectSection(line); sec != "" {
			section = sec
			continue
		}
		trimmed := strings.TrimSpace(line)
		if ggw.parseSection(section, trimmed, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}

func (ggw *GGTLDParser) detectSection(line string) string {
	switch line {
	case "Domain:", "Domain Status:", "Registrant:", "Registrar:", "Relevant dates:", "Registration status:", "Name servers:":
		return line
	}
	return ""
}

func (ggw *GGTLDParser) parseSection(section, trimmed string, parsedWhois *ParsedWhois) bool {
	switch section {
	case "Domain:":
		return ggw.parseDomainSection(trimmed, parsedWhois)
	case "Domain Status:":
		return ggw.parseStatusSection(trimmed, parsedWhois)
	case "Registrant:":
		return ggw.parseRegistrantSection(trimmed, parsedWhois)
	case "Registrar:":
		return ggw.parseRegistrarSection(trimmed, parsedWhois)
	case "Relevant dates:":
		return ggw.parseDatesSection(trimmed, parsedWhois)
	case "Name servers:":
		return ggw.parseNameserversSection(trimmed, parsedWhois)
	}
	return false
}

func (ggw *GGTLDParser) parseDomainSection(trimmed string, parsedWhois *ParsedWhois) bool {
	parsedWhois.DomainName = trimmed
	return true
}

func (ggw *GGTLDParser) parseStatusSection(trimmed string, parsedWhois *ParsedWhois) bool {
	parsedWhois.Statuses = append(parsedWhois.Statuses, trimmed)
	return true
}

func (ggw *GGTLDParser) parseRegistrantSection(trimmed string, parsedWhois *ParsedWhois) bool {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}
	parsedWhois.Contacts.Registrant.Name = trimmed
	return true
}

func (ggw *GGTLDParser) parseRegistrarSection(trimmed string, parsedWhois *ParsedWhois) bool {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}

	if idx := strings.Index(trimmed, "("); idx != -1 {
		parsedWhois.Registrar.Name = strings.TrimSpace(trimmed[:idx])
		parsedWhois.Registrar.URL = strings.TrimSuffix(strings.TrimSpace(trimmed[idx+1:]), ")")
	} else {
		parsedWhois.Registrar.Name = trimmed
	}
	return true
}

func (ggw *GGTLDParser) parseDatesSection(trimmed string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(trimmed, "Registered on ") {
		parsedWhois.CreatedDateRaw = strings.TrimPrefix(trimmed, "Registered on ")
	}
	return true
}

func (ggw *GGTLDParser) parseNameserversSection(trimmed string, parsedWhois *ParsedWhois) bool {
	if ggw.isInvalidNameserver(trimmed) {
		return true
	}
	parsedWhois.NameServers = append(parsedWhois.NameServers, trimmed)
	return true
}

func (ggw *GGTLDParser) isInvalidNameserver(trimmed string) bool {
	return trimmed == "" ||
		strings.Contains(trimmed, " ") ||
		strings.Contains(trimmed, "WHOIS lookup made") ||
		strings.Contains(trimmed, "This WHOIS information") ||
		strings.Contains(trimmed, "Copyright") ||
		strings.Contains(trimmed, "Terms and Conditions")
}
