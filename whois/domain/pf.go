package domain

import (
	"regexp"
	"strings"
)

type PFTLDParser struct {
	parser IParser
}

var pfDomainRe = regexp.MustCompile(`Informations about '([^']+)'`)

func NewPFTLDParser() *PFTLDParser {
	return &PFTLDParser{
		parser: NewParser(),
	}
}

func (pfw *PFTLDParser) GetName() string {
	return "pf"
}

func (pfw *PFTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "Domain unknown") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	// Extract domain name from the "Informations about" line
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Informations about") {
			matches := pfDomainRe.FindStringSubmatch(line)
			if len(matches) == 2 {
				parsedWhois.DomainName = matches[1]
			}
			break
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "This is the PF") || strings.HasPrefix(line, "Informations about") {
			continue
		}

		if strings.HasPrefix(line, "Status :") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status :"))
			if status != "" {
				parsedWhois.Statuses = []string{status}
			}
		} else if strings.HasPrefix(line, "Created (JJ/MM/AAAA) :") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created (JJ/MM/AAAA) :"))
		} else if strings.HasPrefix(line, "Last renewed (JJ/MM/AAAA) :") {
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Last renewed (JJ/MM/AAAA) :"))
		} else if strings.HasPrefix(line, "Expire (JJ/MM/AAAA) :") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expire (JJ/MM/AAAA) :"))
		} else if strings.HasPrefix(line, "Name server") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Name server"))
			if idx := strings.Index(ns, ":"); idx != -1 {
				ns = strings.TrimSpace(ns[idx+1:])
				if ns != "" {
					parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
				}
			}
		} else if strings.Contains(line, " : ") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if strings.HasPrefix(key, "Registrant") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					c := parsedWhois.Contacts.Registrant

					fieldName := strings.TrimSpace(strings.TrimPrefix(key, "Registrant"))
					switch fieldName {
					case "Compagnie Name":
						c.Organization = value
					case "Name":
						c.Name = value
					case "Email":
						c.Email = value
					case "Address":
						c.Street = append(c.Street, value)
					case "Postal Code":
						c.Postal = value
					case "City":
						c.City = value
					case "Region / Island":
						c.State = value
					case "Country":
						c.Country = value
					}
				} else if strings.HasPrefix(key, "Tech 1") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Tech == nil {
						parsedWhois.Contacts.Tech = &Contact{}
					}
					c := parsedWhois.Contacts.Tech

					fieldName := strings.TrimSpace(strings.TrimPrefix(key, "Tech 1"))
					switch fieldName {
					case "Compagnie Name":
						c.Organization = value
					case "Name":
						c.Name = value
					case "Email":
						c.Email = value
					case "Address":
						c.Street = append(c.Street, value)
					case "Postal Code":
						c.Postal = value
					case "City":
						c.City = value
					case "Region / Island":
						c.State = value
					case "Country":
						c.Country = value
					}
				} else if strings.HasPrefix(key, "Registrar") {
					if parsedWhois.Registrar == nil {
						parsedWhois.Registrar = &Registrar{}
					}
					r := parsedWhois.Registrar

					fieldName := strings.TrimSpace(strings.TrimPrefix(key, "Registrar"))
					switch fieldName {
					case "Compagnie Name":
						r.Name = value
					case "Address":
						// Registrar address is typically not stored in the Registrar struct
					case "Postal Code":
						// Registrar postal code is typically not stored
					case "City":
						// Registrar city is typically not stored
					case "Country":
						// Registrar country is typically not stored
					}
				}
			}
		}
	}

	return parsedWhois, nil
}
