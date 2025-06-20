package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TMTLDParser struct {
	parser IParser
}

func NewTMTLDParser() *TMTLDParser {
	return &TMTLDParser{
		parser: NewParser(),
	}
}

func (p *TMTLDParser) GetName() string {
	return "tm"
}

func (p *TMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "is available for purchase") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var registrant Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Domain :") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain :"))
			continue
		}
		if strings.HasPrefix(line, "Status :") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status :"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Expiry :") {
			parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expiry :"))
			continue
		}
		if strings.HasPrefix(line, "Owner Name") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Owner Name"))
			name = strings.TrimSpace(strings.TrimPrefix(name, ":"))
			if name != "" {
				registrant.Name = name
			}
			continue
		}
		if strings.HasPrefix(line, "Owner OrgName") {
			org := strings.TrimSpace(strings.TrimPrefix(line, "Owner OrgName"))
			org = strings.TrimSpace(strings.TrimPrefix(org, ":"))
			if org != "" {
				registrant.Organization = org
			}
			continue
		}
		if strings.HasPrefix(line, "Owner Addr") {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "Owner Addr"))
			addr = strings.TrimSpace(strings.TrimPrefix(addr, ":"))
			if addr != "" {
				registrant.Street = append(registrant.Street, addr)
			}
			continue
		}
	}

	// Dynamic name server detection
	parsed.NameServers = nil
	for _, line := range lines {
		if strings.HasPrefix(line, "NS ") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ns := strings.TrimSpace(parts[1])
				if ns != "" {
					parsed.NameServers = append(parsed.NameServers, ns)
				}
			}
		}
	}

	if registrant.Name != "" || registrant.Organization != "" || len(registrant.Street) > 0 {
		parsed.Contacts.Registrant = &registrant
	}

	// Add date format conversion
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
