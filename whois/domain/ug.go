package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type UGParser struct{}

type UGTLDParser struct {
	parser IParser
}

func NewUGTLDParser() *UGTLDParser {
	return &UGTLDParser{
		parser: NewParser(),
	}
}

func (p *UGTLDParser) GetName() string {
	return "ug"
}

func (p *UGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "The domain contains special characters not allowed") ||
		strings.Contains(rawtext, "This domain violates registry policy") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var section string
	var registrant, admin, tech Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, ">>>") {
			continue
		}

		if strings.HasPrefix(line, "Domain name:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
			continue
		}
		if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Registered On:") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Registered On:"))
			continue
		}
		if strings.HasPrefix(line, "Expires On:") {
			parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expires On:"))
			continue
		}
		if strings.HasPrefix(line, "Nameserver:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Nameserver:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Contact Information:") {
			section = "registrant"
			continue
		}
		if strings.HasPrefix(line, "Administrative Contact Information:") {
			section = "admin"
			continue
		}
		if strings.HasPrefix(line, "Technical Contact Information:") {
			section = "tech"
			continue
		}

		// Parse contact sections
		var c *Contact
		if section == "registrant" {
			c = &registrant
		} else if section == "admin" {
			c = &admin
		} else if section == "tech" {
			c = &tech
		} else {
			continue
		}

		if strings.HasPrefix(line, "Registrant Name:") || strings.HasPrefix(line, "Admin Name:") || strings.HasPrefix(line, "Tech Name:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Name:"))
			name = strings.TrimSpace(strings.TrimPrefix(name, "Admin Name:"))
			name = strings.TrimSpace(strings.TrimPrefix(name, "Tech Name:"))
			if name != "" {
				c.Name = name
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Organization:") || strings.HasPrefix(line, "Admin Organization:") || strings.HasPrefix(line, "Tech Organization:") {
			org := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Organization:"))
			org = strings.TrimSpace(strings.TrimPrefix(org, "Admin Organization:"))
			org = strings.TrimSpace(strings.TrimPrefix(org, "Tech Organization:"))
			if org != "" {
				c.Organization = org
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Country:") || strings.HasPrefix(line, "Admin Country:") || strings.HasPrefix(line, "Tech Country:") {
			country := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Country:"))
			country = strings.TrimSpace(strings.TrimPrefix(country, "Admin Country:"))
			country = strings.TrimSpace(strings.TrimPrefix(country, "Tech Country:"))
			if country != "" && country != "UNKNOWN" {
				c.Country = country
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant State / Province:") || strings.HasPrefix(line, "Admin State / Province:") || strings.HasPrefix(line, "Tech State / Province:") {
			state := strings.TrimSpace(strings.TrimPrefix(line, "Registrant State / Province:"))
			state = strings.TrimSpace(strings.TrimPrefix(state, "Admin State / Province:"))
			state = strings.TrimSpace(strings.TrimPrefix(state, "Tech State / Province:"))
			if state != "" && state != "UNKNOWN" {
				c.State = state
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant City:") || strings.HasPrefix(line, "Admin City:") || strings.HasPrefix(line, "Tech City:") {
			city := strings.TrimSpace(strings.TrimPrefix(line, "Registrant City:"))
			city = strings.TrimSpace(strings.TrimPrefix(city, "Admin City:"))
			city = strings.TrimSpace(strings.TrimPrefix(city, "Tech City:"))
			if city != "" && city != "UNKNOWN" {
				c.City = city
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Address:") || strings.HasPrefix(line, "Admin Address:") || strings.HasPrefix(line, "Tech Address:") {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Address:"))
			addr = strings.TrimSpace(strings.TrimPrefix(addr, "Admin Address:"))
			addr = strings.TrimSpace(strings.TrimPrefix(addr, "Tech Address:"))
			if addr != "" {
				c.Street = append(c.Street, addr)
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Postal Code:") || strings.HasPrefix(line, "Admin Postal Code:") || strings.HasPrefix(line, "Tech Postal Code:") {
			postal := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Postal Code:"))
			postal = strings.TrimSpace(strings.TrimPrefix(postal, "Admin Postal Code:"))
			postal = strings.TrimSpace(strings.TrimPrefix(postal, "Tech Postal Code:"))
			if postal != "" {
				c.Postal = postal
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Phone:") || strings.HasPrefix(line, "Admin Phone:") || strings.HasPrefix(line, "Tech Phone:") {
			phone := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Phone:"))
			phone = strings.TrimSpace(strings.TrimPrefix(phone, "Admin Phone:"))
			phone = strings.TrimSpace(strings.TrimPrefix(phone, "Tech Phone:"))
			if phone != "" && phone != "UNKNOWN" {
				c.Phone = phone
			}
			continue
		}
		if strings.HasPrefix(line, "Registrant Email:") || strings.HasPrefix(line, "Admin Email:") || strings.HasPrefix(line, "Tech Email:") {
			email := strings.TrimSpace(strings.TrimPrefix(line, "Registrant Email:"))
			email = strings.TrimSpace(strings.TrimPrefix(email, "Admin Email:"))
			email = strings.TrimSpace(strings.TrimPrefix(email, "Tech Email:"))
			if email != "" {
				c.Email = email
			}
			continue
		}
	}

	if registrant.Name != "" || registrant.Organization != "" || registrant.Email != "" {
		parsed.Contacts.Registrant = &registrant
	}
	if admin.Name != "" || admin.Organization != "" || admin.Email != "" {
		parsed.Contacts.Admin = &admin
	}
	if tech.Name != "" || tech.Organization != "" || tech.Email != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
