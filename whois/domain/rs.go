package domain

import (
	"strings"
)

type RSTLDParser struct {
	parser IParser
}

func NewRSTLDParser() *RSTLDParser {
	return &RSTLDParser{
		parser: NewParser(),
	}
}

func (r *RSTLDParser) GetName() string {
	return "rs"
}

func (r *RSTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered or reserved domains
	for _, line := range lines {
		if strings.Contains(line, "Domain is not registered") || strings.Contains(line, "This domain is reserved") {
			parsedWhois.Statuses = []string{"free"}
			return parsedWhois, nil
		}
	}

	var currentSection string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		if strings.HasPrefix(line, "Domain name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		} else if strings.HasPrefix(line, "Domain status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Domain status:"))
			// Remove URL if present
			if idx := strings.Index(status, " http"); idx != -1 {
				status = strings.TrimSpace(status[:idx])
			}
			if status != "" {
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
		} else if strings.HasPrefix(line, "Registration date:") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registration date:"))
		} else if strings.HasPrefix(line, "Modification date:") {
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Modification date:"))
		} else if strings.HasPrefix(line, "Expiration date:") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expiration date:"))
		} else if strings.HasPrefix(line, "Registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Registrant:") {
			currentSection = "registrant"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Registrant:"))
		} else if strings.HasPrefix(line, "Administrative contact:") {
			currentSection = "admin"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Admin == nil {
				parsedWhois.Contacts.Admin = &Contact{}
			}
			parsedWhois.Contacts.Admin.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Administrative contact:"))
		} else if strings.HasPrefix(line, "Technical contact:") {
			currentSection = "tech"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Tech == nil {
				parsedWhois.Contacts.Tech = &Contact{}
			}
			parsedWhois.Contacts.Tech.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Technical contact:"))
		} else if strings.HasPrefix(line, "DNS:") {
			nsRaw := strings.TrimSpace(strings.TrimPrefix(line, "DNS:"))
			parsed := nsRaw
			if idx := strings.Index(parsed, " -"); idx != -1 {
				parsed = parsed[:idx]
			}
			parsed = strings.TrimSpace(parsed)
			if parsed != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, parsed)
			}
		} else if strings.HasPrefix(line, "DNSSEC signed:") {
			parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC signed:"))
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch currentSection {
				case "registrant":
					c := parsedWhois.Contacts.Registrant
					switch key {
					case "Address":
						c.Street = append(c.Street, value)
					case "Postal Code":
						c.Postal = value
					case "ID Number":
						c.ID = value
					case "Tax ID":
						// Tax ID is not stored in Contact struct
					}
				case "admin":
					c := parsedWhois.Contacts.Admin
					switch key {
					case "Address":
						c.Street = append(c.Street, value)
					case "Postal Code":
						c.Postal = value
					case "ID Number":
						c.ID = value
					case "Tax ID":
						// Tax ID is not stored in Contact struct
					}
				case "tech":
					c := parsedWhois.Contacts.Tech
					switch key {
					case "Address":
						c.Street = append(c.Street, value)
					case "Postal Code":
						c.Postal = value
					case "ID Number":
						c.ID = value
					case "Tax ID":
						// Tax ID is not stored in Contact struct
					}
				}
			}
		}
	}

	return parsedWhois, nil
}
