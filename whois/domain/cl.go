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

func (clw *CLTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, ": no entries found.") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Domain name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		} else if strings.HasPrefix(line, "Registrant name:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrant name:"))
		} else if strings.HasPrefix(line, "Registrant organisation:") {
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Registrant organisation:"))
		} else if strings.HasPrefix(line, "Registrar name:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar name:"))
		} else if strings.HasPrefix(line, "Registrar URL:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "Registrar URL:"))
		} else if strings.HasPrefix(line, "Creation date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Creation date:"))
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, clTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "Expiration date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Expiration date:"))
			parsedWhois.ExpiredDateRaw = dateStr
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, clTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "Name server:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "Name server:")))
		}
	}

	// Set status to "active" for registered domains
	parsedWhois.Statuses = []string{"active"}

	return parsedWhois, nil
}
