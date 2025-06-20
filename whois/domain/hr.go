package domain

import (
	"strings"
)

type HRTLDParser struct {
	parser IParser
}

func NewHRTLDParser() *HRTLDParser {
	return &HRTLDParser{
		parser: NewParser(),
	}
}

func (hrw *HRTLDParser) GetName() string {
	return "hr"
}

func (hrw *HRTLDParser) handleDomainName(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain Name:") {
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		return true
	}
	return false
}

func (hrw *HRTLDParser) handleRegistrar(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrar:") && !strings.HasPrefix(line, "Registrar WHOIS Server:") && !strings.HasPrefix(line, "Registrar URL:") && !strings.HasPrefix(line, "Registrar Registration Expiration Date:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		return true
	} else if strings.HasPrefix(line, "Registrar WHOIS Server:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.WhoisServer = strings.TrimSpace(strings.TrimPrefix(line, "Registrar WHOIS Server:"))
		return true
	} else if strings.HasPrefix(line, "Registrar URL:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Registrar URL:"))
		return true
	}
	return false
}

func (hrw *HRTLDParser) handleDates(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Updated Date:") {
		parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
		return true
	} else if strings.HasPrefix(line, "Creation Date:") {
		parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
		return true
	} else if strings.HasPrefix(line, "Registrar Registration Expiration Date:") {
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registrar Registration Expiration Date:"))
		return true
	}
	return false
}

func (hrw *HRTLDParser) handleRegistrant(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrant Name:") {
		parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Name:"))
		return true
	} else if strings.HasPrefix(line, "Registrant Street:") {
		street := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Street:"))
		if street != "" {
			parsedWhois.Contacts.Registrant.Street = append(parsedWhois.Contacts.Registrant.Street, street)
		}
		return true
	} else if strings.HasPrefix(line, "Registrant City:") {
		parsedWhois.Contacts.Registrant.City = strings.TrimSpace(strings.TrimPrefix(line, "Registrant City:"))
		return true
	} else if strings.HasPrefix(line, "Registrant Country:") {
		parsedWhois.Contacts.Registrant.Country = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Country:"))
		return true
	} else if strings.HasPrefix(line, "Registrant Postal Code:") {
		parsedWhois.Contacts.Registrant.Postal = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Postal Code:"))
		return true
	} else if strings.HasPrefix(line, "Registrant Email:") {
		parsedWhois.Contacts.Registrant.Email = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Email:"))
		return true
	}
	return false
}

func (hrw *HRTLDParser) handleNameServer(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Name Server:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "Name Server:")))
		return true
	}
	return false
}

func (hrw *HRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{
		Contacts: &Contacts{
			Registrant: &Contact{},
		},
	}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "% No entries found") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if hrw.handleDomainName(line, parsedWhois) {
			continue
		}
		if hrw.handleRegistrar(line, parsedWhois) {
			continue
		}
		if hrw.handleDates(line, parsedWhois) {
			continue
		}
		if hrw.handleRegistrant(line, parsedWhois) {
			continue
		}
		if hrw.handleNameServer(line, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}
