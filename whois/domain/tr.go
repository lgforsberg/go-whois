package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TRTLDParser struct {
	parser IParser
}

func NewTRTLDParser() *TRTLDParser {
	return &TRTLDParser{
		parser: NewParser(),
	}
}

func (p *TRTLDParser) GetName() string {
	return "tr"
}

func (p *TRTLDParser) handleSection(line string, section *string) bool {
	if strings.HasPrefix(line, "** Registrant:") {
		*section = "registrant"
		return true
	}
	if strings.HasPrefix(line, "** Registrar:") {
		*section = "registrar"
		return true
	}
	if strings.HasPrefix(line, "** Domain Servers:") {
		*section = "nameservers"
		return true
	}
	if strings.HasPrefix(line, "** Additional Info:") {
		*section = "additional"
		return true
	}
	if strings.HasPrefix(line, "** Whois Server:") {
		*section = "whois"
		return true
	}
	return false
}

func (p *TRTLDParser) parseRegistrant(line string, registrant *Contact) {
	if line != "" && !strings.HasPrefix(line, "**") {
		if registrant.Name == "" {
			registrant.Name = line
		} else {
			registrant.Street = append(registrant.Street, line)
		}
	}
}

func (p *TRTLDParser) parseRegistrar(line string, i *int, lines []string, parsed *ParsedWhois, admin *Contact) {
	if strings.HasPrefix(line, "NIC Handle") {
		parsed.Registrar.IanaID = strings.TrimSpace(strings.TrimPrefix(line, "NIC Handle"))
		parsed.Registrar.IanaID = strings.TrimPrefix(parsed.Registrar.IanaID, ":")
		parsed.Registrar.IanaID = strings.TrimSpace(parsed.Registrar.IanaID)
	} else if strings.HasPrefix(line, "Organization Name") {
		parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Organization Name"))
		parsed.Registrar.Name = strings.TrimPrefix(parsed.Registrar.Name, ":")
		parsed.Registrar.Name = strings.TrimSpace(parsed.Registrar.Name)
	} else if strings.HasPrefix(line, "Address") {
		addr := strings.TrimSpace(strings.TrimPrefix(line, "Address"))
		addr = strings.TrimPrefix(addr, ":")
		addr = strings.TrimSpace(addr)
		if addr != "" {
			admin.Street = append(admin.Street, addr)
		}
		// Check for indented address lines
		for j := *i + 1; j < len(lines); j++ {
			if strings.HasPrefix(lines[j], "  ") || strings.HasPrefix(lines[j], "\t") {
				admin.Street = append(admin.Street, strings.TrimSpace(lines[j]))
				*i = j
			} else {
				break
			}
		}
	} else if strings.HasPrefix(line, "Phone") {
		parsed.Registrar.AbuseContactPhone = strings.TrimSpace(strings.TrimPrefix(line, "Phone"))
		parsed.Registrar.AbuseContactPhone = strings.TrimPrefix(parsed.Registrar.AbuseContactPhone, ":")
		parsed.Registrar.AbuseContactPhone = strings.TrimSpace(parsed.Registrar.AbuseContactPhone)
	} else if strings.HasPrefix(line, "Fax") {
		admin.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax"))
		admin.Fax = strings.TrimPrefix(admin.Fax, ":")
		admin.Fax = strings.TrimSpace(admin.Fax)
	}
}

func (p *TRTLDParser) parseNameServers(line string, parsed *ParsedWhois) {
	if line != "" && !strings.HasPrefix(line, "**") {
		parsed.NameServers = append(parsed.NameServers, line)
	}
}

func (p *TRTLDParser) parseAdditionalInfo(line string, parsed *ParsedWhois) {
	if strings.HasPrefix(line, "Created on") {
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created on..............:"))
	} else if strings.HasPrefix(line, "Expires on") {
		parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires on..............:"))
	}
}

func (p *TRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "No match found for") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var section string
	var registrant, admin Contact

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if p.parseTopLevelFields(line, parsed) {
			continue
		}
		if p.handleSection(line, &section) {
			continue
		}

		// Section parsing
		switch section {
		case "registrant":
			p.parseRegistrant(line, &registrant)
		case "registrar":
			p.parseRegistrar(line, &i, lines, parsed, &admin)
		case "nameservers":
			p.parseNameServers(line, parsed)
		case "additional":
			p.parseAdditionalInfo(line, parsed)
		}
	}

	if registrant.Name != "" {
		parsed.Contacts.Registrant = &registrant
	}
	if admin.Name != "" || len(admin.Street) > 0 || admin.Fax != "" {
		parsed.Contacts.Admin = &admin
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *TRTLDParser) parseTopLevelFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "** Domain Name:"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "** Domain Name:"))
		return true
	case strings.HasPrefix(line, "Domain Status:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Frozen Status:"):
		frozen := strings.TrimSpace(strings.TrimPrefix(line, "Frozen Status:"))
		if frozen != "-" && frozen != "" {
			parsed.Statuses = append(parsed.Statuses, "Frozen: "+frozen)
		}
		return true
	case strings.HasPrefix(line, "Transfer Status:"):
		transfer := strings.TrimSpace(strings.TrimPrefix(line, "Transfer Status:"))
		if transfer != "" {
			parsed.Statuses = append(parsed.Statuses, "Transfer: "+transfer)
		}
		return true
	}
	return false
}
