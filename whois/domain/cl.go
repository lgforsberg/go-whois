package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	clTimeFmt = "2006-01-02 15:04:05 MST"
)

type CLParser struct{}

type CLTLDParser struct {
	parser IParser
}

func NewCLTLDParser() *CLTLDParser {
	return &CLTLDParser{
		parser: NewParser(),
	}
}

func (clw *CLTLDParser) GetName() string {
	return "cl"
}

func (clw *CLTLDParser) handleDomainName(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain name:") {
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		return true
	}
	return false
}

func (clw *CLTLDParser) handleContact(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrant name:") {
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrant name:"))
		return true
	} else if strings.HasPrefix(line, "Registrant organisation:") {
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		parsedWhois.Contacts.Registrant.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Registrant organisation:"))
		return true
	}
	return false
}

func (clw *CLTLDParser) handleRegistrar(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrar name:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar name:"))
		return true
	} else if strings.HasPrefix(line, "Registrar URL:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Registrar URL:"))
		return true
	}
	return false
}

func (clw *CLTLDParser) handleDates(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Creation date:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Creation date:"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, clTimeFmt, WhoisTimeFmt)
		return true
	} else if strings.HasPrefix(line, "Expiration date:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Expiration date:"))
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, clTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (clw *CLTLDParser) handleNameServer(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Name server:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "Name server:")))
		return true
	}
	return false
}

func (clw *CLTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, ": no entries found.") {
		parsedWhois := &ParsedWhois{
			Statuses: []string{"free"},
		}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{
		Contacts: &Contacts{},
	}
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if clw.handleDomainName(line, parsedWhois) {
			continue
		}
		if clw.handleContact(line, parsedWhois) {
			continue
		}
		if clw.handleRegistrar(line, parsedWhois) {
			continue
		}
		if clw.handleDates(line, parsedWhois) {
			continue
		}
		if clw.handleNameServer(line, parsedWhois) {
			continue
		}
	}

	// Set status to "active" for registered domains
	parsedWhois.Statuses = []string{"active"}

	return parsedWhois, nil
}
