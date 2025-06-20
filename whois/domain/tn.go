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
		if p.skipLine(line) {
			continue
		}

		if p.handleSectionHeaders(line, parsed, &section) {
			continue
		}

		if section == "dns" {
			p.handleDNSSection(line, parsed)
			continue
		}

		p.handleContactSection(line, section, &owner, &admin, &tech)
	}

	p.assignContacts(parsed, &owner, &admin, &tech)

	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *TNTLDParser) skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "NIC Whois") ||
		strings.HasPrefix(line, "All rights") || strings.HasPrefix(line, "Copyright") ||
		strings.HasPrefix(line, "Supported ccTLDs") || strings.HasPrefix(line, "Sectorial domains") ||
		strings.HasPrefix(line, "Details:")
}

func (p *TNTLDParser) handleSectionHeaders(line string, parsed *ParsedWhois, section *string) bool {
	switch {
	case strings.HasPrefix(line, "Domain name"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name"))
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(parsed.DomainName, ".........:"))
		return true
	case strings.HasPrefix(line, "Creation date"):
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Creation date"))
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(parsed.CreatedDateRaw, ".......:"))
		return true
	case strings.HasPrefix(line, "Domain status"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Domain status"))
		status = strings.TrimSpace(strings.TrimPrefix(status, ".......:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Registrar"):
		parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar"))
		parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(parsed.Registrar.Name, "...........:"))
		return true
	case strings.HasPrefix(line, "dnssec"):
		parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "dnssec"))
		parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(parsed.Dnssec, "..............:"))
		return true
	case line == "Owner Contact":
		*section = "owner"
		return true
	case line == "Administrativ contact":
		*section = "admin"
		return true
	case line == "Technical contact":
		*section = "tech"
		return true
	case line == "DNS servers":
		*section = "dns"
		return true
	}
	return false
}

func (p *TNTLDParser) handleDNSSection(line string, parsed *ParsedWhois) {
	if strings.HasPrefix(line, "Name") {
		ns := strings.TrimSpace(strings.TrimPrefix(line, "Name"))
		ns = strings.TrimSpace(strings.TrimPrefix(ns, "................:"))
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
	}
}

func (p *TNTLDParser) handleContactSection(line, section string, owner, admin, tech *Contact) {
	var c *Contact
	switch section {
	case "owner":
		c = owner
	case "admin":
		c = admin
	case "tech":
		c = tech
	default:
		return
	}

	p.parseContactField(line, c)
}

func (p *TNTLDParser) parseContactField(line string, c *Contact) {
	if p.parseNameFields(line, c) {
		return
	}
	if p.parseAddressFields(line, c) {
		return
	}
	if p.parseContactInfoFields(line, c) {
		return
	}
}

func (p *TNTLDParser) parseNameFields(line string, c *Contact) bool {
	switch {
	case strings.HasPrefix(line, "Name"):
		name := p.extractFieldValue(line, "Name", "................:")
		if name != "" {
			c.Name = name
		}
		return true
	case strings.HasPrefix(line, "First name"):
		firstName := p.extractFieldValue(line, "First name", "..........:")
		if firstName != "" && c.Name != "" {
			c.Name = firstName + " " + c.Name
		} else if firstName != "" {
			c.Name = firstName
		}
		return true
	}
	return false
}

func (p *TNTLDParser) parseAddressFields(line string, c *Contact) bool {
	switch {
	case strings.HasPrefix(line, "Address"):
		addr := p.extractFieldValue(line, "Address", ".............:")
		if addr != "" {
			c.Street = append(c.Street, addr)
		}
		return true
	case strings.HasPrefix(line, "address2"):
		addr2 := p.extractFieldValue(line, "address2", "............:")
		if addr2 != "" {
			c.Street = append(c.Street, addr2)
		}
		return true
	case strings.HasPrefix(line, "City"):
		city := p.extractFieldValue(line, "City", "................:")
		if city != "" {
			c.City = city
		}
		return true
	case strings.HasPrefix(line, "stateProvince"):
		state := p.extractFieldValue(line, "stateProvince", ".......:")
		if state != "" {
			c.State = state
		}
		return true
	case strings.HasPrefix(line, "Zip code"):
		postal := p.extractFieldValue(line, "Zip code", "............:")
		if postal != "" {
			c.Postal = postal
		}
		return true
	case strings.HasPrefix(line, "Country"):
		country := p.extractFieldValue(line, "Country", ".............:")
		if country != "" {
			c.Country = country
		}
		return true
	}
	return false
}

func (p *TNTLDParser) parseContactInfoFields(line string, c *Contact) bool {
	switch {
	case strings.HasPrefix(line, "Phone"):
		phone := p.extractFieldValue(line, "Phone", "...............:")
		if phone != "" {
			c.Phone = phone
		}
		return true
	case strings.HasPrefix(line, "Fax"):
		fax := p.extractFieldValue(line, "Fax", "................:")
		if fax != "" {
			c.Fax = fax
		}
		return true
	case strings.HasPrefix(line, "Email"):
		email := p.extractFieldValue(line, "Email", "...............:")
		if email != "" {
			c.Email = email
		}
		return true
	}
	return false
}

func (p *TNTLDParser) extractFieldValue(line, prefix, separator string) string {
	value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	return strings.TrimSpace(strings.TrimPrefix(value, separator))
}

func (p *TNTLDParser) assignContacts(parsed *ParsedWhois, owner, admin, tech *Contact) {
	if owner.Name != "" || owner.Organization != "" || owner.Email != "" {
		parsed.Contacts.Registrant = owner
	}
	if admin.Name != "" || admin.Organization != "" || admin.Email != "" {
		parsed.Contacts.Admin = admin
	}
	if tech.Name != "" || tech.Organization != "" || tech.Email != "" {
		parsed.Contacts.Tech = tech
	}
}
