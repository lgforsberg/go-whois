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
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var registrant, tech Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Whois Server") ||
			strings.HasPrefix(line, ">>>") || strings.HasPrefix(line, "If you have") ||
			strings.HasPrefix(line, "For more information") {
			continue
		}

		if strings.HasPrefix(line, "Domain Name:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
			continue
		}
		if strings.HasPrefix(line, "Registrar:") {
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
			continue
		}
		if strings.HasPrefix(line, "Name Server:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Name Server:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
			continue
		}
		if strings.HasPrefix(line, "DNSSEC:") {
			parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
			continue
		}
		if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Updated date:") {
			parsed.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Updated date:"))
			continue
		}
		if strings.HasPrefix(line, "Created date:") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created date:"))
			continue
		}
		if strings.HasPrefix(line, "Exp date:") {
			parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Exp date:"))
			continue
		}
		if strings.HasPrefix(line, "Domain Holder Organization:") {
			org := strings.TrimSpace(strings.TrimPrefix(line, "Domain Holder Organization:"))
			if org != "" && org != "Personal Information" {
				registrant.Organization = org
			}
			continue
		}
		if strings.HasPrefix(line, "Domain Holder Street:") {
			street := strings.TrimSpace(strings.TrimPrefix(line, "Domain Holder Street:"))
			if street != "" && street != "Personal Information" {
				registrant.Street = append(registrant.Street, street)
			}
			continue
		}
		if strings.HasPrefix(line, "Domain Holder Country:") {
			country := strings.TrimSpace(strings.TrimPrefix(line, "Domain Holder Country:"))
			if country != "" && country != "Personal Information" {
				registrant.Country = country
			}
			continue
		}
		if strings.HasPrefix(line, "Tech Contact:") {
			contact := strings.TrimSpace(strings.TrimPrefix(line, "Tech Contact:"))
			if contact != "" && contact != "Personal Information" {
				tech.Name = contact
			}
			continue
		}
		if strings.HasPrefix(line, "Tech Organization:") {
			org := strings.TrimSpace(strings.TrimPrefix(line, "Tech Organization:"))
			if org != "" && org != "Personal Information" {
				tech.Organization = org
			}
			continue
		}
		if strings.HasPrefix(line, "Tech Street:") {
			street := strings.TrimSpace(strings.TrimPrefix(line, "Tech Street:"))
			if street != "" && street != "Personal Information" {
				tech.Street = append(tech.Street, street)
			}
			continue
		}
		if strings.HasPrefix(line, "Tech Country:") {
			country := strings.TrimSpace(strings.TrimPrefix(line, "Tech Country:"))
			if country != "" && country != "Personal Information" {
				tech.Country = country
			}
			continue
		}
	}

	if registrant.Organization != "" || len(registrant.Street) > 0 || registrant.Country != "" {
		parsed.Contacts.Registrant = &registrant
	}
	if tech.Name != "" || tech.Organization != "" || len(tech.Street) > 0 || tech.Country != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.UpdatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
