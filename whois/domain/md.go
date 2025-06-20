package domain

import (
	"regexp"
	"strings"
)

type MDTLDParser struct {
	parser IParser
}

var mdExpiresRe = regexp.MustCompile(`Expires\s+on\s+([0-9\-]+)$`)

func NewMDTLDParser() *MDTLDParser {
	return &MDTLDParser{
		parser: NewParser(),
	}
}

func (mdw *MDTLDParser) GetName() string {
	return "md"
}

func (mdw *MDTLDParser) handleBasicFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain  name") {
		parsedWhois.DomainName = getMDValue(line, "Domain  name")
		return true
	} else if strings.HasPrefix(line, "Domain state") {
		status := getMDValue(line, "Domain state")
		if status != "" {
			parsedWhois.Statuses = []string{status}
		}
		return true
	} else if strings.HasPrefix(line, "Nameserver") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, getMDValue(line, "Nameserver"))
		return true
	}
	return false
}

func (mdw *MDTLDParser) handleContactFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrant") {
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Name = getMDValue(line, "Registrant")
		return true
	}
	return false
}

func (mdw *MDTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registered on") {
		parsedWhois.CreatedDateRaw = getMDValue(line, "Registered on")
		return true
	} else if strings.HasPrefix(line, "Expires") {
		parsedWhois.ExpiredDateRaw = getMDValue(line, "Expires")
		return true
	}
	return false
}

func (mdw *MDTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "No match for") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if mdw.handleBasicFields(line, parsedWhois) {
			continue
		}
		if mdw.handleContactFields(line, parsedWhois) {
			continue
		}
		if mdw.handleDateFields(line, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}

func getMDValue(line, prefix string) string {
	if prefix == "Expires" {
		matches := mdExpiresRe.FindStringSubmatch(line)
		if len(matches) == 2 {
			return matches[1]
		}
	} else {
		parts := strings.SplitN(line, prefix, 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
