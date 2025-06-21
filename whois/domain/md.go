package domain

import (
	"regexp"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
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
		parsedWhois.DomainName = mdw.extractMDValue(line, "Domain  name")
		return true
	} else if strings.HasPrefix(line, "Domain state") {
		status := mdw.extractMDValue(line, "Domain state")
		if status != "" {
			parsedWhois.Statuses = []string{status}
		}
		return true
	} else if strings.HasPrefix(line, "Nameserver") {
		if utils.IsNameserverLine(line, "Nameserver") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, mdw.extractMDValue(line, "Nameserver"))
		}
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
		parsedWhois.Contacts.Registrant.Name = mdw.extractMDValue(line, "Registrant")
		return true
	}
	return false
}

func (mdw *MDTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registered on") {
		parsedWhois.CreatedDateRaw = mdw.extractMDValue(line, "Registered on")
		return true
	} else if strings.HasPrefix(line, "Expires") {
		// Special handling for "Expires    on   2026-05-02" format
		matches := mdExpiresRe.FindStringSubmatch(line)
		if len(matches) == 2 {
			parsedWhois.ExpiredDateRaw = matches[1]
		} else {
			parsedWhois.ExpiredDateRaw = mdw.extractMDValue(line, "Expires")
		}
		return true
	}
	return false
}

// extractMDValue extracts the value after the prefix, handling MD's multiple-space format
func (mdw *MDTLDParser) extractMDValue(line, prefix string) string {
	parts := strings.SplitN(line, prefix, 2)
	if len(parts) > 1 {
		return strings.TrimSpace(parts[1])
	}
	return ""
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
