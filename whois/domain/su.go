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
		SetDomainAvailabilityStatus(parsed, true)
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "Last updated") {
			continue
		}
		if p.parseDomainAndRegistrar(line, parsed) {
			continue
		}
		if p.parseNameServers(line, parsed) {
			continue
		}
		if p.parseStatus(line, parsed) {
			continue
		}
		if p.parseContactInfo(line, parsed) {
			continue
		}
		if p.parseDates(line, parsed) {
			continue
		}
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *SUTLDParser) parseDomainAndRegistrar(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "domain:"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
		return true
	case strings.HasPrefix(line, "registrar:"):
		parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
		return true
	}
	return false
}

func (p *SUTLDParser) parseNameServers(line string, parsed *ParsedWhois) bool {
	if strings.HasPrefix(line, "nserver:") {
		ns := strings.TrimSpace(strings.TrimPrefix(line, "nserver:"))
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
		return true
	}
	return false
}

func (p *SUTLDParser) parseStatus(line string, parsed *ParsedWhois) bool {
	if strings.HasPrefix(line, "state:") {
		status := strings.TrimSpace(strings.TrimPrefix(line, "state:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	}
	return false
}

func (p *SUTLDParser) parseContactInfo(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "person:"):
		person := strings.TrimSpace(strings.TrimPrefix(line, "person:"))
		if person != "" {
			parsed.Contacts.Registrant = &Contact{
				Name: person,
			}
		}
		return true
	case strings.HasPrefix(line, "e-mail:"):
		email := strings.TrimSpace(strings.TrimPrefix(line, "e-mail:"))
		if email != "" && parsed.Contacts.Registrant != nil {
			parsed.Contacts.Registrant.Email = email
		}
		return true
	}
	return false
}

func (p *SUTLDParser) parseDates(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "created:"):
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "created:"))
		return true
	case strings.HasPrefix(line, "paid-till:"):
		parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "paid-till:"))
		return true
	}
	return false
}
