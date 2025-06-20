package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type SUTLDParser struct {
	parser IParser
}

func NewSUTLDParser() *SUTLDParser {
	return &SUTLDParser{
		parser: NewParser(),
	}
}

func (p *SUTLDParser) GetName() string {
	return "su"
}

func (p *SUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "No entries found for the selected source(s).") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "Last updated") {
			continue
		}
		if strings.HasPrefix(line, "domain:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
			continue
		}
		if strings.HasPrefix(line, "nserver:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nserver:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
			continue
		}
		if strings.HasPrefix(line, "state:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "state:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "person:") {
			person := strings.TrimSpace(strings.TrimPrefix(line, "person:"))
			if person != "" {
				parsed.Contacts.Registrant = &Contact{
					Name: person,
				}
			}
			continue
		}
		if strings.HasPrefix(line, "e-mail:") {
			email := strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
			if email != "" && parsed.Contacts.Registrant != nil {
				parsed.Contacts.Registrant.Email = email
			}
			continue
		}
		if strings.HasPrefix(line, "registrar:") {
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
			continue
		}
		if strings.HasPrefix(line, "created:") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "created:"))
			continue
		}
		if strings.HasPrefix(line, "paid-till:") {
			parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "paid-till:"))
			continue
		}
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
