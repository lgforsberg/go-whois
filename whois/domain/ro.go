package domain

import (
	"strings"
)

type ROTLDParser struct {
	parser IParser
}

func NewROTLDParser() *ROTLDParser {
	return &ROTLDParser{
		parser: NewParser(),
	}
}

func (r *ROTLDParser) GetName() string {
	return "ro"
}

func (r *ROTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered domains
	for _, line := range lines {
		if strings.Contains(line, "No entries found for the selected source") {
			parsedWhois.Statuses = []string{"free"}
			return parsedWhois, nil
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Registered On:") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registered On:"))
		} else if strings.HasPrefix(line, "Expires On:") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires On:"))
		} else if strings.HasPrefix(line, "Registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Referral URL:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Referral URL:"))
		} else if strings.HasPrefix(line, "DNSSEC:") {
			parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
		} else if strings.HasPrefix(line, "Nameserver:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Nameserver:"))
			if ns != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		} else if strings.HasPrefix(line, "Domain Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
			if status != "" {
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
		}
	}

	return parsedWhois, nil
}
