package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type LTTLDParser struct {
	parser IParser
}

func NewLTTLDParser() *LTTLDParser {
	return &LTTLDParser{
		parser: NewParser(),
	}
}

func (ltw *LTTLDParser) GetName() string {
	return "lt"
}

func (ltw *LTTLDParser) handleBasicFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain:"):
		parsedWhois.DomainName = strings.TrimSpace(utils.ExtractValue(line))
		return true
	case strings.HasPrefix(line, "Status:"):
		status := strings.TrimSpace(utils.ExtractValue(line))
		if status == "available" {
			SetDomainAvailabilityStatus(parsedWhois, true)
			return true
		}
		parsedWhois.Statuses = []string{status}
		return true
	case strings.HasPrefix(line, "Registered:"):
		parsedWhois.CreatedDateRaw = strings.TrimSpace(utils.ExtractValue(line))
		return true
	case strings.HasPrefix(line, "Expires:"):
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(utils.ExtractValue(line))
		return true
	case strings.HasPrefix(line, "Nameserver:"):
		if utils.IsNameserverLine(line, "Nameserver:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(utils.ExtractValue(line)))
		}
		return true
	}
	return false
}

func (ltw *LTTLDParser) handleRegistrarFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Registrar:"):
		if utils.IsRegistrarLine(line, "Registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(utils.ExtractValue(line))
		}
		return true
	case strings.HasPrefix(line, "Registrar website:"):
		if utils.IsRegistrarLine(line, "Registrar website:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(utils.ExtractValue(line))
		}
		return true
	case strings.HasPrefix(line, "Registrar email:"):
		// Registrar struct does not have an Email field, so skip this line
		return true
	}
	return false
}

func (ltw *LTTLDParser) handleContactFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Contact organization:"):
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Organization = strings.TrimSpace(utils.ExtractValue(line))
		return true
	case strings.HasPrefix(line, "Contact email:"):
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Email = strings.TrimSpace(utils.ExtractValue(line))
		return true
	}
	return false
}

func (ltw *LTTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		// Handle basic fields
		if ltw.handleBasicFields(line, parsedWhois) {
			continue
		}

		// Handle registrar fields
		if ltw.handleRegistrarFields(line, parsedWhois) {
			continue
		}

		// Handle contact fields
		ltw.handleContactFields(line, parsedWhois)
	}
	return parsedWhois, nil
}
