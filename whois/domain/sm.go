package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type SMTLDParser struct {
	parser IParser
}

func NewSMTLDParser() *SMTLDParser {
	return &SMTLDParser{
		parser: NewParser(),
	}
}

func (p *SMTLDParser) GetName() string {
	return "sm"
}

func (p *SMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "No entries found.") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	section := ""
	var owner Contact
	var tech Contact

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if p.parseTopLevelFields(line, parsed) {
			continue
		}
		if sec := p.handleSectionChange(line); sec != "" {
			section = sec
			continue
		}
		if section == "owner" {
			if p.parseOwnerSection(line, &owner) {
				continue
			}
		}
		if section == "tech" {
			if p.parseTechSection(line, &tech) {
				continue
			}
		}
		if section == "dns" {
			p.parseDNSSection(line, parsed)
			continue
		}
	}

	if owner.Name != "" {
		parsed.Contacts.Registrant = &owner
	}
	if tech.Name != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *SMTLDParser) parseTopLevelFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name:"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		return true
	case strings.HasPrefix(line, "Registration date:"):
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registration date:"))
		return true
	case strings.HasPrefix(line, "Status:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	}
	return false
}

func (p *SMTLDParser) handleSectionChange(line string) string {
	switch line {
	case "Owner:":
		return "owner"
	case "Technical Contact:":
		return "tech"
	case "DNS Servers:":
		return "dns"
	}
	return ""
}

func (p *SMTLDParser) parseOwnerSection(line string, owner *Contact) bool {
	if owner.Name == "" {
		owner.Name = line
		return true
	}
	if strings.HasPrefix(line, "Phone:") {
		owner.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
		return true
	}
	if strings.HasPrefix(line, "Fax:") {
		owner.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
		return true
	}
	if strings.HasPrefix(line, "Email:") {
		owner.Email = strings.TrimSpace(strings.TrimPrefix(line, "Email:"))
		return true
	}
	// Address lines
	owner.Street = append(owner.Street, line)
	return true
}

func (p *SMTLDParser) parseTechSection(line string, tech *Contact) bool {
	if tech.Name == "" {
		tech.Name = line
		return true
	}
	if tech.Organization == "" {
		tech.Organization = line
		return true
	}
	if strings.HasPrefix(line, "Phone:") {
		tech.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
		return true
	}
	if strings.HasPrefix(line, "Fax:") {
		tech.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
		return true
	}
	if strings.HasPrefix(line, "Email:") {
		tech.Email = strings.TrimSpace(strings.TrimPrefix(line, "Email:"))
		return true
	}
	// Address lines
	tech.Street = append(tech.Street, line)
	return true
}

func (p *SMTLDParser) parseDNSSection(line string, parsed *ParsedWhois) {
	parsed.NameServers = append(parsed.NameServers, line)
}
