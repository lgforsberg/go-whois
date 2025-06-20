package domain

import (
	"errors"
	"strings"
)

type LUTLDParser struct {
	parser IParser
}

func NewLUTLDParser() *LUTLDParser {
	return &LUTLDParser{
		parser: NewParser(),
	}
}

func (luw *LUTLDParser) GetName() string {
	return "lu"
}

func (luw *LUTLDParser) handleBasicFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "domainname:") {
		parsedWhois.DomainName = getLUValue(line)
		return true
	} else if strings.HasPrefix(line, "domaintype:") {
		parsedWhois.Statuses = []string{getLUValue(line)}
		return true
	} else if strings.HasPrefix(line, "nserver:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, getLUValue(line))
		return true
	}
	return false
}

func (luw *LUTLDParser) handleRegistrarFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "registrar-name:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = getLUValue(line)
		return true
	} else if strings.HasPrefix(line, "registrar-url:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = getLUValue(line)
		return true
	}
	return false
}

func (luw *LUTLDParser) handleContactFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "org-country:") {
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Country = getLUValue(line)
		return true
	}
	return false
}

func (luw *LUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "%% Maximum query rate reached") {
		return nil, errors.New("rate limit reached for .lu whois server")
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if luw.handleBasicFields(line, parsedWhois) {
			continue
		}
		if luw.handleRegistrarFields(line, parsedWhois) {
			continue
		}
		if luw.handleContactFields(line, parsedWhois) {
			continue
		}
	}

	if parsedWhois.DomainName == "" {
		parsedWhois.Statuses = []string{"free"}
	}

	return parsedWhois, nil
}

func getLUValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
