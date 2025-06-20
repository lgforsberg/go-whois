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

func (lvw *LVTLDParser) handleDomainSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Domain:") {
		parsedWhois.DomainName = getLVValue(line)
	} else if strings.HasPrefix(line, "Status:") {
		status := getLVValue(line)
		if status == "free" {
			parsedWhois.Statuses = []string{"free"}
			return
		}
		parsedWhois.Statuses = []string{status}
	}
}

func (lvw *LVTLDParser) handleHolderSection(line string, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}

	if strings.HasPrefix(line, "Name:") {
		parsedWhois.Contacts.Registrant.Name = getLVValue(line)
	} else if strings.HasPrefix(line, "Country:") {
		parsedWhois.Contacts.Registrant.Country = getLVValue(line)
	} else if strings.HasPrefix(line, "Address:") {
		parsedWhois.Contacts.Registrant.Street = []string{getLVValue(line)}
	}
}

func (lvw *LVTLDParser) handleRegistrarSection(line string, parsedWhois *ParsedWhois) {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	if strings.HasPrefix(line, "Name:") {
		parsedWhois.Registrar.Name = getLVValue(line)
	}
}

func (lvw *LVTLDParser) handleNserversSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Nserver:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, getLVValue(line))
	}
}

func (lvw *LVTLDParser) handleWhoisSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Updated:") {
		parsedWhois.UpdatedDateRaw = getLVValue(line)
	}
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
			lvw.handleDomainSection(line, parsedWhois)
			if parsedWhois.Statuses != nil && parsedWhois.Statuses[0] == "free" {
				return parsedWhois, nil
			}
		case "Holder":
			lvw.handleHolderSection(line, parsedWhois)
		case "Registrar":
			lvw.handleRegistrarSection(line, parsedWhois)
		case "Nservers":
			lvw.handleNserversSection(line, parsedWhois)
		case "Whois":
			lvw.handleWhoisSection(line, parsedWhois)
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
