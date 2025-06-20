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
		if line == "Domain:" || line == "Domain Status:" || line == "Registrant:" || line == "Registrar:" || line == "Relevant dates:" || line == "Registration status:" || line == "Name servers:" {
			section = line
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch section {
		case "Domain:":
			parsedWhois.DomainName = trimmed
		case "Domain Status:":
			parsedWhois.Statuses = append(parsedWhois.Statuses, trimmed)
		case "Registrant:":
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = trimmed
		case "Registrar:":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			if idx := strings.Index(trimmed, "("); idx != -1 {
				parsedWhois.Registrar.Name = strings.TrimSpace(trimmed[:idx])
				parsedWhois.Registrar.URL = strings.TrimSuffix(strings.TrimSpace(trimmed[idx+1:]), ")")
			} else {
				parsedWhois.Registrar.Name = trimmed
			}
		case "Relevant dates:":
			if strings.HasPrefix(trimmed, "Registered on ") {
				parsedWhois.CreatedDateRaw = strings.TrimPrefix(trimmed, "Registered on ")
			}
		case "Name servers:":
			if trimmed == "" || strings.Contains(trimmed, " ") || strings.Contains(trimmed, "WHOIS lookup made") || strings.Contains(trimmed, "This WHOIS information") || strings.Contains(trimmed, "Copyright") || strings.Contains(trimmed, "Terms and Conditions") {
				break
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, trimmed)
		}
	}

	return parsedWhois, nil
}
