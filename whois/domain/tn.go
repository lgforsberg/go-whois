package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TNParser struct{}

type TNTLDParser struct {
	parser IParser
}

func NewTNTLDParser() *TNTLDParser {
	return &TNTLDParser{
		parser: NewParser(),
	}
}

func (p *TNTLDParser) GetName() string {
	return "tn"
}

func (p *TNTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Dnssec:      "",
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "NO OBJECT FOUND!") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var section string
	var owner, admin, tech Contact

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "NIC Whois") ||
			strings.HasPrefix(line, "All rights") || strings.HasPrefix(line, "Copyright") ||
			strings.HasPrefix(line, "Supported ccTLDs") || strings.HasPrefix(line, "Sectorial domains") ||
			strings.HasPrefix(line, "Details:") {
			continue
		}

		if strings.HasPrefix(line, "Domain name") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name"))
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(parsed.DomainName, ".........:"))
			continue
		}
		if strings.HasPrefix(line, "Creation date") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Creation date"))
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(parsed.CreatedDateRaw, ".......:"))
			continue
		}
		if strings.HasPrefix(line, "Domain status") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Domain status"))
			status = strings.TrimSpace(strings.TrimPrefix(status, ".......:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Registrar") {
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar"))
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(parsed.Registrar.Name, "...........:"))
			continue
		}
		if strings.HasPrefix(line, "dnssec") {
			parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "dnssec"))
			parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(parsed.Dnssec, "..............:"))
			continue
		}
		if line == "Owner Contact" {
			section = "owner"
			continue
		}
		if line == "Administrativ contact" {
			section = "admin"
			continue
		}
		if line == "Technical contact" {
			section = "tech"
			continue
		}
		if line == "DNS servers" {
			section = "dns"
			continue
		}

		// Parse contact sections
		var c *Contact
		if section == "owner" {
			c = &owner
		} else if section == "admin" {
			c = &admin
		} else if section == "tech" {
			c = &tech
		} else if section == "dns" {
			// Handle nameservers
			if strings.HasPrefix(line, "Name") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "Name"))
				ns = strings.TrimSpace(strings.TrimPrefix(ns, "................:"))
				if ns != "" {
					parsed.NameServers = append(parsed.NameServers, ns)
				}
			}
			continue
		} else {
			continue
		}

		if strings.HasPrefix(line, "Name") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Name"))
			name = strings.TrimSpace(strings.TrimPrefix(name, "................:"))
			if name != "" {
				c.Name = name
			}
			continue
		}
		if strings.HasPrefix(line, "First name") {
			firstName := strings.TrimSpace(strings.TrimPrefix(line, "First name"))
			firstName = strings.TrimSpace(strings.TrimPrefix(firstName, "..........:"))
			if firstName != "" && c.Name != "" {
				c.Name = firstName + " " + c.Name
			} else if firstName != "" {
				c.Name = firstName
			}
			continue
		}
		if strings.HasPrefix(line, "Address") {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "Address"))
			addr = strings.TrimSpace(strings.TrimPrefix(addr, ".............:"))
			if addr != "" {
				c.Street = append(c.Street, addr)
			}
			continue
		}
		if strings.HasPrefix(line, "address2") {
			addr2 := strings.TrimSpace(strings.TrimPrefix(line, "address2"))
			addr2 = strings.TrimSpace(strings.TrimPrefix(addr2, "............:"))
			if addr2 != "" {
				c.Street = append(c.Street, addr2)
			}
			continue
		}
		if strings.HasPrefix(line, "City") {
			city := strings.TrimSpace(strings.TrimPrefix(line, "City"))
			city = strings.TrimSpace(strings.TrimPrefix(city, "................:"))
			if city != "" {
				c.City = city
			}
			continue
		}
		if strings.HasPrefix(line, "stateProvince") {
			state := strings.TrimSpace(strings.TrimPrefix(line, "stateProvince"))
			state = strings.TrimSpace(strings.TrimPrefix(state, ".......:"))
			if state != "" {
				c.State = state
			}
			continue
		}
		if strings.HasPrefix(line, "Zip code") {
			postal := strings.TrimSpace(strings.TrimPrefix(line, "Zip code"))
			postal = strings.TrimSpace(strings.TrimPrefix(postal, "............:"))
			if postal != "" {
				c.Postal = postal
			}
			continue
		}
		if strings.HasPrefix(line, "Country") {
			country := strings.TrimSpace(strings.TrimPrefix(line, "Country"))
			country = strings.TrimSpace(strings.TrimPrefix(country, ".............:"))
			if country != "" {
				c.Country = country
			}
			continue
		}
		if strings.HasPrefix(line, "Phone") {
			phone := strings.TrimSpace(strings.TrimPrefix(line, "Phone"))
			phone = strings.TrimSpace(strings.TrimPrefix(phone, "...............:"))
			if phone != "" {
				c.Phone = phone
			}
			continue
		}
		if strings.HasPrefix(line, "Fax") {
			fax := strings.TrimSpace(strings.TrimPrefix(line, "Fax"))
			fax = strings.TrimSpace(strings.TrimPrefix(fax, "................:"))
			if fax != "" {
				c.Fax = fax
			}
			continue
		}
		if strings.HasPrefix(line, "Email") {
			email := strings.TrimSpace(strings.TrimPrefix(line, "Email"))
			email = strings.TrimSpace(strings.TrimPrefix(email, "...............:"))
			if email != "" {
				c.Email = email
			}
			continue
		}
	}

	if owner.Name != "" {
		parsed.Contacts.Registrant = &owner
	}
	if admin.Name != "" {
		parsed.Contacts.Admin = &admin
	}
	if tech.Name != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)

	return parsed, nil
}
