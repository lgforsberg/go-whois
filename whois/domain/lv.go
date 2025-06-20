package domain

import (
	"strings"
)

type LVTLDParser struct {
	parser IParser
}

func NewLVTLDParser() *LVTLDParser {
	return &LVTLDParser{
		parser: NewParser(),
	}
}

func (lvw *LVTLDParser) GetName() string {
	return "lv"
}

func (lvw *LVTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		switch currentSection {
		case "Domain":
			if strings.HasPrefix(line, "Domain:") {
				parsedWhois.DomainName = getLVValue(line)
			} else if strings.HasPrefix(line, "Status:") {
				status := getLVValue(line)
				if status == "free" {
					parsedWhois.Statuses = []string{"free"}
					return parsedWhois, nil
				}
				parsedWhois.Statuses = []string{status}
			}
		case "Holder":
			if strings.HasPrefix(line, "Name:") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Name = getLVValue(line)
			} else if strings.HasPrefix(line, "Country:") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Country = getLVValue(line)
			} else if strings.HasPrefix(line, "Address:") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Street = []string{getLVValue(line)}
			}
		case "Tech":
			if strings.HasPrefix(line, "Type:") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Tech == nil {
					parsedWhois.Contacts.Tech = &Contact{}
				}
				// Note: Contact struct doesn't have Type field, so skip
			}
		case "Registrar":
			if strings.HasPrefix(line, "Name:") {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				parsedWhois.Registrar.Name = getLVValue(line)
			} else if strings.HasPrefix(line, "Address:") {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				// Note: Registrar struct doesn't have Address field, so skip
			}
		case "Nservers":
			if strings.HasPrefix(line, "Nserver:") {
				parsedWhois.NameServers = append(parsedWhois.NameServers, getLVValue(line))
			}
		case "Whois":
			if strings.HasPrefix(line, "Updated:") {
				parsedWhois.UpdatedDateRaw = getLVValue(line)
			}
		}
	}

	return parsedWhois, nil
}

func getLVValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
