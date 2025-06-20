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
		if strings.HasPrefix(line, "** Domain Name:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "** Domain Name:"))
			continue
		}
		if strings.HasPrefix(line, "Domain Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Frozen Status:") {
			frozen := strings.TrimSpace(strings.TrimPrefix(line, "Frozen Status:"))
			if frozen != "-" && frozen != "" {
				parsed.Statuses = append(parsed.Statuses, "Frozen: "+frozen)
			}
			continue
		}
		if strings.HasPrefix(line, "Transfer Status:") {
			transfer := strings.TrimSpace(strings.TrimPrefix(line, "Transfer Status:"))
			if transfer != "" {
				parsed.Statuses = append(parsed.Statuses, "Transfer: "+transfer)
			}
			continue
		}
		if strings.HasPrefix(line, "** Registrant:") {
			section = "registrant"
			continue
		}
		if strings.HasPrefix(line, "** Registrar:") {
			section = "registrar"
			continue
		}
		if strings.HasPrefix(line, "** Domain Servers:") {
			section = "nameservers"
			continue
		}
		if strings.HasPrefix(line, "** Additional Info:") {
			section = "additional"
			continue
		}
		if strings.HasPrefix(line, "** Whois Server:") {
			section = "whois"
			continue
		}

		// Section parsing
		if section == "registrant" {
			if line != "" && !strings.HasPrefix(line, "**") {
				if registrant.Name == "" {
					registrant.Name = line
				} else {
					registrant.Street = append(registrant.Street, line)
				}
			}
			continue
		}
		if section == "registrar" {
			if strings.HasPrefix(line, "NIC Handle") {
				parsed.Registrar.IanaID = strings.TrimSpace(strings.TrimPrefix(line, "NIC Handle"))
				parsed.Registrar.IanaID = strings.TrimPrefix(parsed.Registrar.IanaID, ":")
				parsed.Registrar.IanaID = strings.TrimSpace(parsed.Registrar.IanaID)
				continue
			}
			if strings.HasPrefix(line, "Organization Name") {
				parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Organization Name"))
				parsed.Registrar.Name = strings.TrimPrefix(parsed.Registrar.Name, ":")
				parsed.Registrar.Name = strings.TrimSpace(parsed.Registrar.Name)
				continue
			}
			if strings.HasPrefix(line, "Address") {
				addr := strings.TrimSpace(strings.TrimPrefix(line, "Address"))
				addr = strings.TrimPrefix(addr, ":")
				addr = strings.TrimSpace(addr)
				if addr != "" {
					admin.Street = append(admin.Street, addr)
				}
				// Check for indented address lines
				for j := i + 1; j < len(lines); j++ {
					if strings.HasPrefix(lines[j], "  ") || strings.HasPrefix(lines[j], "\t") {
						admin.Street = append(admin.Street, strings.TrimSpace(lines[j]))
						i = j
					} else {
						break
					}
				}
				continue
			}
			if strings.HasPrefix(line, "Phone") {
				parsed.Registrar.AbuseContactPhone = strings.TrimSpace(strings.TrimPrefix(line, "Phone"))
				parsed.Registrar.AbuseContactPhone = strings.TrimPrefix(parsed.Registrar.AbuseContactPhone, ":")
				parsed.Registrar.AbuseContactPhone = strings.TrimSpace(parsed.Registrar.AbuseContactPhone)
				continue
			}
			if strings.HasPrefix(line, "Fax") {
				admin.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax"))
				admin.Fax = strings.TrimPrefix(admin.Fax, ":")
				admin.Fax = strings.TrimSpace(admin.Fax)
				continue
			}
			continue
		}
		if section == "nameservers" {
			if line != "" && !strings.HasPrefix(line, "**") {
				parsed.NameServers = append(parsed.NameServers, line)
			}
			continue
		}
		if section == "additional" {
			if strings.HasPrefix(line, "Created on") {
				parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created on..............:"))
				continue
			}
			if strings.HasPrefix(line, "Expires on") {
				parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires on..............:"))
				continue
			}
			continue
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
