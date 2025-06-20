package domain

import (
	"strings"
)

type HKTLDParser struct {
	parser IParser
}

func NewHKTLDParser() *HKTLDParser {
	return &HKTLDParser{
		parser: NewParser(),
	}
}

func (hkw *HKTLDParser) GetName() string {
	return "hk"
}

func (hkw *HKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if strings.Contains(rawtext, "This domain is currently not available for registration") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	var currentContact *Contact

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(trimmed, "Domain Name:") {
			section = "domain"
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Name:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Domain Status:") {
			section = "status"
			status := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Status:"))
			if status != "" {
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "DNSSEC:") {
			section = "dnssec"
			parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(trimmed, "DNSSEC:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Registrar Name:") {
			section = "registrar"
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Registrar Name:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Registrar Contact Information:") {
			section = "registrar_contact"
			continue
		}
		if strings.HasPrefix(trimmed, "Registrant Contact Information:") {
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
		if strings.HasPrefix(trimmed, "Administrative Contact Information:") {
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
		if strings.HasPrefix(trimmed, "Technical Contact Information:") {
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
		if strings.HasPrefix(trimmed, "Name Servers Information:") {
			section = "nameservers"
			continue
		}
		if strings.HasPrefix(trimmed, "Status Information:") {
			section = "status_info"
			continue
		}

		// Parse content based on current section
		switch section {
		case "registrar_contact":
			if strings.HasPrefix(trimmed, "Email:") {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				parsedWhois.Registrar.AbuseContactEmail = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
			}
		case "registrant":
			if strings.HasPrefix(trimmed, "Company English Name") {
				if currentContact != nil {
					currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(trimmed, "Company English Name (It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents):"))
				}
			} else if strings.HasPrefix(trimmed, "Address:") {
				if currentContact != nil {
					address := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
					if address != "" {
						currentContact.Street = append(currentContact.Street, address)
					}
				}
			} else if strings.HasPrefix(trimmed, "Country:") {
				if currentContact != nil {
					currentContact.Country = strings.TrimSpace(strings.TrimPrefix(trimmed, "Country:"))
				}
			} else if strings.HasPrefix(trimmed, "Email:") {
				if currentContact != nil {
					currentContact.Email = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
				}
			} else if strings.HasPrefix(trimmed, "Domain Name Commencement Date:") {
				date := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Name Commencement Date:"))
				if date != "" {
					parsedWhois.CreatedDateRaw = date
				}
			} else if strings.HasPrefix(trimmed, "Expiry Date:") {
				date := strings.TrimSpace(strings.TrimPrefix(trimmed, "Expiry Date:"))
				if date != "" {
					parsedWhois.ExpiredDateRaw = date
				}
			}
		case "admin", "tech":
			if strings.HasPrefix(trimmed, "Given name:") {
				if currentContact != nil {
					currentContact.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Given name:"))
				}
			} else if strings.HasPrefix(trimmed, "Family name:") {
				if currentContact != nil && currentContact.Name != "" {
					currentContact.Name += " " + strings.TrimSpace(strings.TrimPrefix(trimmed, "Family name:"))
				} else if currentContact != nil {
					currentContact.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Family name:"))
				}
			} else if strings.HasPrefix(trimmed, "Company name:") {
				if currentContact != nil {
					currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(trimmed, "Company name:"))
				}
			} else if strings.HasPrefix(trimmed, "Address:") {
				if currentContact != nil {
					address := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
					if address != "" {
						currentContact.Street = append(currentContact.Street, address)
					}
				}
			} else if strings.HasPrefix(trimmed, "Country:") {
				if currentContact != nil {
					currentContact.Country = strings.TrimSpace(strings.TrimPrefix(trimmed, "Country:"))
				}
			} else if strings.HasPrefix(trimmed, "Phone:") {
				if currentContact != nil {
					currentContact.Phone = strings.TrimSpace(strings.TrimPrefix(trimmed, "Phone:"))
				}
			} else if strings.HasPrefix(trimmed, "Fax:") {
				if currentContact != nil {
					currentContact.Fax = strings.TrimSpace(strings.TrimPrefix(trimmed, "Fax:"))
				}
			} else if strings.HasPrefix(trimmed, "Email:") {
				if currentContact != nil {
					currentContact.Email = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
				}
			}
		case "nameservers":
			if trimmed != "" && !strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "WHOIS") && !strings.Contains(trimmed, "Copyright") && !strings.Contains(trimmed, "Terms") {
				parsedWhois.NameServers = append(parsedWhois.NameServers, trimmed)
			}
		case "status_info":
			if strings.HasPrefix(trimmed, "Domain Prohibit Status:") {
				status := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Prohibit Status:"))
				if status != "" {
					parsedWhois.Statuses = append(parsedWhois.Statuses, status)
				}
			}
		}
	}

	return parsedWhois, nil
}
