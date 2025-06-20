package domain

import (
	"strings"
)

type KZTLDParser struct {
	parser IParser
}

func NewKZTLDParser() *KZTLDParser {
	return &KZTLDParser{
		parser: NewParser(),
	}
}

func (kzw *KZTLDParser) GetName() string {
	return "kz"
}

func (kzw *KZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "Nothing found for this query") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	var section string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Whois Server") || strings.HasPrefix(line, "This server") {
			continue
		}

		if strings.HasPrefix(line, "Domain Name") {
			parsedWhois.DomainName = getKZValue(line)
		} else if line == "Organization Using Domain Name" {
			section = "organization"
		} else if line == "Administrative Contact/Agent" {
			section = "admin"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Admin == nil {
				parsedWhois.Contacts.Admin = &Contact{}
			}
		} else if line == "Nameserver in listed order" {
			section = "nameservers"
		} else if strings.HasPrefix(line, "Domain created") {
			parsedWhois.CreatedDateRaw = getKZValue(line)
		} else if strings.HasPrefix(line, "Last modified") {
			parsedWhois.UpdatedDateRaw = getKZValue(line)
		} else if strings.HasPrefix(line, "Domain status") {
			status := getKZValue(line)
			if status != "" {
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
		} else if strings.HasPrefix(line, "Current Registar") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = getKZValue(line)
		} else {
			switch section {
			case "organization":
				if strings.HasPrefix(line, "Name") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.Name = getKZValue(line)
				} else if strings.HasPrefix(line, "Organization Name") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.Organization = getKZValue(line)
				} else if strings.HasPrefix(line, "Street Address") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.Street = []string{getKZValue(line)}
				} else if strings.HasPrefix(line, "City") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.City = getKZValue(line)
				} else if strings.HasPrefix(line, "State") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.State = getKZValue(line)
				} else if strings.HasPrefix(line, "Postal Code") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.Postal = getKZValue(line)
				} else if strings.HasPrefix(line, "Country") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Registrant == nil {
						parsedWhois.Contacts.Registrant = &Contact{}
					}
					parsedWhois.Contacts.Registrant.Country = getKZValue(line)
				}
			case "admin":
				if strings.HasPrefix(line, "Name") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Admin == nil {
						parsedWhois.Contacts.Admin = &Contact{}
					}
					parsedWhois.Contacts.Admin.Name = getKZValue(line)
				} else if strings.HasPrefix(line, "Phone Number") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Admin == nil {
						parsedWhois.Contacts.Admin = &Contact{}
					}
					parsedWhois.Contacts.Admin.Phone = getKZValue(line)
				} else if strings.HasPrefix(line, "Fax Number") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Admin == nil {
						parsedWhois.Contacts.Admin = &Contact{}
					}
					parsedWhois.Contacts.Admin.Fax = getKZValue(line)
				} else if strings.HasPrefix(line, "Email Address") {
					if parsedWhois.Contacts == nil {
						parsedWhois.Contacts = &Contacts{}
					}
					if parsedWhois.Contacts.Admin == nil {
						parsedWhois.Contacts.Admin = &Contact{}
					}
					parsedWhois.Contacts.Admin.Email = getKZValue(line)
				}
			case "nameservers":
				if strings.HasPrefix(line, "Primary server") {
					parsedWhois.NameServers = append(parsedWhois.NameServers, getKZValue(line))
				} else if strings.HasPrefix(line, "Secondary server") {
					parsedWhois.NameServers = append(parsedWhois.NameServers, getKZValue(line))
				}
			}
		}
	}

	return parsedWhois, nil
}

func getKZValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
