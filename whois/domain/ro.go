package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
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
		parsedWhois.DomainName = utils.ExtractField(line, "Domain Name:")
		return true
	} else if strings.HasPrefix(line, "DNSSEC:") {
		parsedWhois.Dnssec = utils.ExtractField(line, "DNSSEC:")
		return true
	} else if strings.HasPrefix(line, "Domain Status:") {
		status := utils.ExtractField(line, "Domain Status:")
		if status != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		}
		return true
	}
	return false
}

func (r *ROTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registered On:") {
		parsedWhois.CreatedDateRaw = utils.ExtractField(line, "Registered On:")
		return true
	} else if strings.HasPrefix(line, "Expires On:") {
		parsedWhois.ExpiredDateRaw = utils.ExtractField(line, "Expires On:")
		return true
	}
	return false
}

func (r *ROTLDParser) handleRegistrarFields(line string, parsedWhois *ParsedWhois) bool {
	if utils.IsRegistrarLine(line, "Registrar:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = utils.ExtractField(line, "Registrar:")
		return true
	} else if strings.HasPrefix(line, "Referral URL:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = utils.ExtractField(line, "Referral URL:")
		return true
	}
	return false
}

func (r *ROTLDParser) handleNameServerFields(line string, parsedWhois *ParsedWhois) bool {
	if utils.IsNameserverLine(line, "Nameserver:") {
		ns := utils.ExtractField(line, "Nameserver:")
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
			SetDomainAvailabilityStatus(parsedWhois, true)
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
