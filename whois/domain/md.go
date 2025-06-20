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

		if strings.HasPrefix(line, "Domain  name") {
			parsedWhois.DomainName = getMDValue(line)
		} else if strings.HasPrefix(line, "Domain state") {
			status := getMDValue(line)
			if status != "" {
				parsedWhois.Statuses = []string{status}
			}
		} else if strings.HasPrefix(line, "Registrant") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = getMDValue(line)
		} else if strings.HasPrefix(line, "Registered on") {
			parsedWhois.CreatedDateRaw = getMDValue(line)
		} else if strings.HasPrefix(line, "Expires") {
			parsedWhois.ExpiredDateRaw = getMDValue(line)
		} else if strings.HasPrefix(line, "Nameserver") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, getMDValue(line))
		}
	}

	return parsedWhois, nil
}

func getMDValue(line string) string {
	if strings.HasPrefix(line, "Domain  name") {
		parts := strings.SplitN(line, "Domain  name", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(line, "Domain state") {
		parts := strings.SplitN(line, "Domain state", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(line, "Registrant") {
		parts := strings.SplitN(line, "Registrant", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(line, "Registered on") {
		parts := strings.SplitN(line, "Registered on", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	} else if strings.HasPrefix(line, "Expires") {
		// Use regex to extract the date
		matches := mdExpiresRe.FindStringSubmatch(line)
		if len(matches) == 2 {
			return matches[1]
		}
	} else if strings.HasPrefix(line, "Nameserver") {
		parts := strings.SplitN(line, "Nameserver", 2)
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
