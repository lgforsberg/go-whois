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

func (r *ROTLDParser) handleBasicFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain Name:") {
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		return true
	} else if strings.HasPrefix(line, "DNSSEC:") {
		parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
		return true
	} else if strings.HasPrefix(line, "Domain Status:") {
		status := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
		if status != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		}
		return true
	}
	return false
}

func (r *ROTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registered On:") {
		parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registered On:"))
		return true
	} else if strings.HasPrefix(line, "Expires On:") {
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires On:"))
		return true
	}
	return false
}

func (r *ROTLDParser) handleRegistrarFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrar:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		return true
	} else if strings.HasPrefix(line, "Referral URL:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Referral URL:"))
		return true
	}
	return false
}

func (r *ROTLDParser) handleNameServerFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Nameserver:") {
		ns := strings.TrimSpace(strings.TrimPrefix(line, "Nameserver:"))
		if ns != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
		return true
	}
	return false
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
		if r.handleBasicFields(line, parsedWhois) {
			continue
		}
		if r.handleDateFields(line, parsedWhois) {
			continue
		}
		if r.handleRegistrarFields(line, parsedWhois) {
			continue
		}
		if r.handleNameServerFields(line, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}
