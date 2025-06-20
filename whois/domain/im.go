package domain

import (
	"strings"
)

type IMTLDParser struct {
	parser IParser
}

func NewIMTLDParser() *IMTLDParser {
	return &IMTLDParser{
		parser: NewParser(),
	}
}

func (imw *IMTLDParser) GetName() string {
	return "im"
}

func (imw *IMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	var currentContact *Contact
	var expectRegistrarName, expectContactName bool

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
			continue
		}
		if line == "Domain Managers" {
			section = "registrar"
			continue
		}
		if line == "Domain Owners / Registrant" {
			section = "registrant"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			currentContact = parsedWhois.Contacts.Registrant
			continue
		}
		if line == "Administrative Contact" {
			section = "admin"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Admin == nil {
				parsedWhois.Contacts.Admin = &Contact{}
			}
			currentContact = parsedWhois.Contacts.Admin
			continue
		}
		if line == "Billing Contact" {
			section = "billing"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Billing == nil {
				parsedWhois.Contacts.Billing = &Contact{}
			}
			currentContact = parsedWhois.Contacts.Billing
			continue
		}
		if line == "Technical Contact" {
			section = "tech"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Tech == nil {
				parsedWhois.Contacts.Tech = &Contact{}
			}
			currentContact = parsedWhois.Contacts.Tech
			continue
		}
		if line == "Domain Details" {
			section = "details"
			continue
		}

		// Handle expected name value after 'Name' line
		if expectRegistrarName {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			if line != "Redacted" {
				parsedWhois.Registrar.Name = line
			}
			expectRegistrarName = false
			continue
		}
		if expectContactName && currentContact != nil {
			if line != "Redacted" {
				currentContact.Name = line
			}
			expectContactName = false
			continue
		}

		// Parse content based on current section
		switch section {
		case "registrar":
			if strings.HasPrefix(line, "Name:") {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				registrarName := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				if registrarName != "Redacted" {
					parsedWhois.Registrar.Name = registrarName
				}
			} else if line == "Name" {
				expectRegistrarName = true
			} else if parsedWhois.Registrar != nil && parsedWhois.Registrar.Name == "" && line != "" && !strings.HasPrefix(line, "Address") {
				if line != "Redacted" {
					parsedWhois.Registrar.Name = line
				}
			}
		case "registrant", "admin", "billing", "tech":
			if strings.HasPrefix(line, "Name:") {
				if currentContact != nil {
					name := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
					if name != "Redacted" {
						currentContact.Name = name
					}
				}
			} else if line == "Name" {
				expectContactName = true
			} else if currentContact != nil && currentContact.Name == "" && line != "" && !strings.HasPrefix(line, "Address") && line != "Address" {
				if line != "Redacted" {
					currentContact.Name = line
				}
			} else if line == "Address" {
				// Address section starts, will be handled by next lines
			} else if currentContact != nil && line != "" && !strings.HasPrefix(line, "Name:") && line != "Name" && line != "Address" {
				if currentContact.Street == nil {
					currentContact.Street = []string{}
				}
				if line != "Redacted" {
					currentContact.Street = append(currentContact.Street, line)
				}
			}
		case "details":
			if strings.HasPrefix(line, "Expiry Date:") {
				date := strings.TrimSpace(strings.TrimPrefix(line, "Expiry Date:"))
				if date != "" {
					parsedWhois.ExpiredDateRaw = date
				}
			} else if strings.HasPrefix(line, "Name Server:") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "Name Server:"))
				if ns != "" {
					parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
				}
			}
		}
	}

	return parsedWhois, nil
}
