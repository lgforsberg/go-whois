package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type THTLDParser struct {
	parser IParser
}

func NewTHTLDParser() *THTLDParser {
	return &THTLDParser{
		parser: NewParser(),
	}
}

func (p *THTLDParser) GetName() string {
	return "th"
}

func (p *THTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		UpdatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Dnssec:      "",
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "% No match found.") {
		SetDomainAvailabilityStatus(parsed, true)
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var registrant, tech Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if p.skipLine(line) {
			continue
		}
		if p.parseDomainFields(line, parsed) {
			continue
		}
		if p.parseContactFields(line, &registrant, &tech) {
			continue
		}
	}

	if registrant.Organization != "" || len(registrant.Street) > 0 || registrant.Country != "" {
		parsed.Contacts.Registrant = &registrant
	}
	if tech.Name != "" || tech.Organization != "" || len(tech.Street) > 0 || tech.Country != "" {
		parsed.Contacts.Tech = &tech
	}

	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.UpdatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *THTLDParser) skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "Whois Server") ||
		strings.HasPrefix(line, ">>>") || strings.HasPrefix(line, "If you have") ||
		strings.HasPrefix(line, "For more information")
}

func (p *THTLDParser) parseDomainFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name:"):
		parsed.DomainName = utils.ExtractField(line, "Domain Name:")
		return true
	case strings.HasPrefix(line, "Registrar:"):
		parsed.Registrar.Name = utils.ExtractField(line, "Registrar:")
		return true
	case strings.HasPrefix(line, "Name Server:"):
		ns := utils.ExtractField(line, "Name Server:")
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
		return true
	case strings.HasPrefix(line, "DNSSEC:"):
		parsed.Dnssec = utils.ExtractField(line, "DNSSEC:")
		return true
	case strings.HasPrefix(line, "Status:"):
		status := utils.ExtractField(line, "Status:")
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Updated date:"):
		parsed.UpdatedDateRaw = utils.ExtractField(line, "Updated date:")
		return true
	case strings.HasPrefix(line, "Created date:"):
		parsed.CreatedDateRaw = utils.ExtractField(line, "Created date:")
		return true
	case strings.HasPrefix(line, "Exp date:"):
		parsed.ExpiredDateRaw = utils.ExtractField(line, "Exp date:")
		return true
	}
	return false
}

func (p *THTLDParser) parseContactFields(line string, registrant, tech *Contact) bool {
	switch {
	case strings.HasPrefix(line, "Domain Holder Organization:"):
		return p.parseRegistrantOrganization(line, registrant)
	case strings.HasPrefix(line, "Domain Holder Street:"):
		return p.parseRegistrantStreet(line, registrant)
	case strings.HasPrefix(line, "Domain Holder Country:"):
		return p.parseRegistrantCountry(line, registrant)
	case strings.HasPrefix(line, "Tech Contact:"):
		return p.parseTechContact(line, tech)
	case strings.HasPrefix(line, "Tech Organization:"):
		return p.parseTechOrganization(line, tech)
	case strings.HasPrefix(line, "Tech Street:"):
		return p.parseTechStreet(line, tech)
	case strings.HasPrefix(line, "Tech Country:"):
		return p.parseTechCountry(line, tech)
	}
	return false
}

func (p *THTLDParser) parseRegistrantOrganization(line string, registrant *Contact) bool {
	org := p.extractField(line, "Domain Holder Organization:")
	if p.isValidField(org) {
		registrant.Organization = org
	}
	return true
}

func (p *THTLDParser) parseRegistrantStreet(line string, registrant *Contact) bool {
	street := p.extractField(line, "Domain Holder Street:")
	if p.isValidField(street) {
		registrant.Street = append(registrant.Street, street)
	}
	return true
}

func (p *THTLDParser) parseRegistrantCountry(line string, registrant *Contact) bool {
	country := p.extractField(line, "Domain Holder Country:")
	if p.isValidField(country) {
		registrant.Country = country
	}
	return true
}

func (p *THTLDParser) parseTechContact(line string, tech *Contact) bool {
	contact := p.extractField(line, "Tech Contact:")
	if p.isValidField(contact) {
		tech.Name = contact
	}
	return true
}

func (p *THTLDParser) parseTechOrganization(line string, tech *Contact) bool {
	org := p.extractField(line, "Tech Organization:")
	if p.isValidField(org) {
		tech.Organization = org
	}
	return true
}

func (p *THTLDParser) parseTechStreet(line string, tech *Contact) bool {
	street := p.extractField(line, "Tech Street:")
	if p.isValidField(street) {
		tech.Street = append(tech.Street, street)
	}
	return true
}

func (p *THTLDParser) parseTechCountry(line string, tech *Contact) bool {
	country := p.extractField(line, "Tech Country:")
	if p.isValidField(country) {
		tech.Country = country
	}
	return true
}

func (p *THTLDParser) isValidField(value string) bool {
	return value != "" && value != "Personal Information"
}

func (p *THTLDParser) extractField(line, prefix string) string {
	return utils.ExtractField(line, prefix)
}
