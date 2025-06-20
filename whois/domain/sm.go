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
	var section string
	var owner Contact
	var tech Contact

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Domain Name:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
			continue
		}
		if strings.HasPrefix(line, "Registration date:") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registration date:"))
			continue
		}
		if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if line == "Owner:" {
			section = "owner"
			continue
		}
		if line == "Technical Contact:" {
			section = "tech"
			continue
		}
		if line == "DNS Servers:" {
			section = "dns"
			continue
		}

		// Parse section details
		if section == "owner" {
			if owner.Name == "" {
				owner.Name = line
				continue
			}
			if strings.HasPrefix(line, "Phone:") {
				owner.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
				continue
			}
			if strings.HasPrefix(line, "Fax:") {
				owner.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
				continue
			}
			if strings.HasPrefix(line, "Email:") {
				owner.Email = strings.TrimSpace(strings.TrimPrefix(line, "Email:"))
				continue
			}
			// Address lines
			owner.Street = append(owner.Street, line)
			continue
		}
		if section == "tech" {
			if tech.Name == "" {
				tech.Name = line
				continue
			}
			if tech.Organization == "" {
				tech.Organization = line
				continue
			}
			if strings.HasPrefix(line, "Phone:") {
				tech.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Phone:"))
				continue
			}
			if strings.HasPrefix(line, "Fax:") {
				tech.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
				continue
			}
			if strings.HasPrefix(line, "Email:") {
				tech.Email = strings.TrimSpace(strings.TrimPrefix(line, "Email:"))
				continue
			}
			// Address lines
			tech.Street = append(tech.Street, line)
			continue
		}
		if section == "dns" {
			parsed.NameServers = append(parsed.NameServers, line)
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
