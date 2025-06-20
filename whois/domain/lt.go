package domain

import (
	"regexp"
	"strings"
)

type LTTLDParser struct {
	parser IParser
}

var ltLeadingWS = regexp.MustCompile(`^[ \t]+`)

func NewLTTLDParser() *LTTLDParser {
	return &LTTLDParser{
		parser: NewParser(),
	}
}

func (ltw *LTTLDParser) GetName() string {
	return "lt"
}

func (ltw *LTTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "Domain:") {
			parsedWhois.DomainName = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(getLTValue(line))
			if status == "available" {
				parsedWhois.Statuses = []string{"free"}
				return parsedWhois, nil
			}
			parsedWhois.Statuses = []string{status}
		} else if strings.HasPrefix(line, "Registered:") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Expires:") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Registrar website:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Registrar email:") {
			// Registrar struct does not have an Email field, so skip this line
			continue
		} else if strings.HasPrefix(line, "Contact organization:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Organization = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Contact email:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Email = strings.TrimSpace(getLTValue(line))
		} else if strings.HasPrefix(line, "Nameserver:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(getLTValue(line)))
		}
	}
	return parsedWhois, nil
}

func getLTValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	val := line[idx+1:]
	val = ltLeadingWS.ReplaceAllString(val, "")
	return strings.TrimSpace(val)
}
