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

func (hrw *HRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
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
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Registrar:") && !strings.HasPrefix(line, "Registrar WHOIS Server:") && !strings.HasPrefix(line, "Registrar URL:") && !strings.HasPrefix(line, "Registrar Registration Expiration Date:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Registrar WHOIS Server:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.WhoisServer = strings.TrimSpace(strings.TrimPrefix(line, "Registrar WHOIS Server:"))
		} else if strings.HasPrefix(line, "Registrar URL:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Registrar URL:"))
		} else if strings.HasPrefix(line, "Updated Date:") {
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
		} else if strings.HasPrefix(line, "Creation Date:") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
		} else if strings.HasPrefix(line, "Registrar Registration Expiration Date:") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registrar Registration Expiration Date:"))
		} else if strings.HasPrefix(line, "Registrant Name:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Name:"))
		} else if strings.HasPrefix(line, "Registrant Street:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			street := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Street:"))
			if street != "" {
				parsedWhois.Contacts.Registrant.Street = append(parsedWhois.Contacts.Registrant.Street, street)
			}
		} else if strings.HasPrefix(line, "Registrant City:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.City = strings.TrimSpace(strings.TrimPrefix(line, "Registrant City:"))
		} else if strings.HasPrefix(line, "Registrant Country:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Country = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Country:"))
		} else if strings.HasPrefix(line, "Registrant Postal Code:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Postal = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Postal Code:"))
		} else if strings.HasPrefix(line, "Registrant Email:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Email = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Email:"))
		} else if strings.HasPrefix(line, "Name Server:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "Name Server:")))
		}
	}

	return parsedWhois, nil
}
