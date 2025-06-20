package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type SNTLDParser struct {
	parser IParser
}

func NewSNTLDParser() *SNTLDParser {
	return &SNTLDParser{
		parser: NewParser(),
	}
}

func (p *SNTLDParser) GetName() string {
	return "sn"
}

func (p *SNTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
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

	if strings.Contains(rawtext, "%% NOT FOUND") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var section string
	var billing, tech, holder, admin Contact

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if p.skipLine(line) {
			continue
		}
		if p.parseDomainFields(line, parsed) {
			continue
		}
		if p.handleSectionChange(line, &section) {
			continue
		}
		if p.parseContactFields(line, section, &billing, &tech, &holder, &admin) {
			continue
		}
	}

	if billing.Name != "" {
		parsed.Contacts.Billing = &billing
	}
	if tech.Name != "" {
		parsed.Contacts.Tech = &tech
	}
	if holder.Name != "" {
		parsed.Contacts.Registrant = &holder
	}
	if admin.Name != "" {
		parsed.Contacts.Admin = &admin
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.UpdatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func (p *SNTLDParser) skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "=") || strings.HasPrefix(line, ">>>")
}

func (p *SNTLDParser) parseDomainFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Nom de domaine:"):
		parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Nom de domaine:"))
		return true
	case strings.HasPrefix(line, "Date de création:"):
		parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Date de création:"))
		return true
	case strings.HasPrefix(line, "Dernière modification:"):
		parsed.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Dernière modification:"))
		return true
	case strings.HasPrefix(line, "Date d'expiration:"):
		parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Date d'expiration:"))
		return true
	case strings.HasPrefix(line, "Registrar:"):
		parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		return true
	case strings.HasPrefix(line, "Statut:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Statut:"))
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Serveur de noms:"):
		ns := strings.TrimSpace(strings.TrimPrefix(line, "Serveur de noms:"))
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
		return true
	case strings.HasPrefix(line, "DNSSEC:"):
		parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
		return true
	}
	return false
}

func (p *SNTLDParser) handleSectionChange(line string, section *string) bool {
	switch line {
	case "[BILLING_C]":
		*section = "billing"
		return true
	case "[TECH_C]":
		*section = "tech"
		return true
	case "[HOLDER]":
		*section = "holder"
		return true
	case "[ADMIN_C]":
		*section = "admin"
		return true
	}
	return false
}

func (p *SNTLDParser) parseContactFields(line, section string, billing, tech, holder, admin *Contact) bool {
	var c *Contact
	switch section {
	case "billing":
		c = billing
	case "tech":
		c = tech
	case "holder":
		c = holder
	case "admin":
		c = admin
	default:
		return false
	}

	return p.assignContactField(line, c)
}

func (p *SNTLDParser) assignContactField(line string, c *Contact) bool {
	switch {
	case strings.HasPrefix(line, "ID Contact:"):
		c.ID = strings.TrimSpace(strings.TrimPrefix(line, "ID Contact:"))
		return true
	case strings.HasPrefix(line, "Nom:"):
		c.Name = strings.TrimSpace(strings.TrimPrefix(line, "Nom:"))
		return true
	case strings.HasPrefix(line, "Adresse:"):
		c.Street = append(c.Street, strings.TrimSpace(strings.TrimPrefix(line, "Adresse:")))
		return true
	case strings.HasPrefix(line, "Code postal:"):
		c.Postal = strings.TrimSpace(strings.TrimPrefix(line, "Code postal:"))
		return true
	case strings.HasPrefix(line, "Ville:"):
		c.City = strings.TrimSpace(strings.TrimPrefix(line, "Ville:"))
		return true
	case strings.HasPrefix(line, "Pays:"):
		c.Country = strings.TrimSpace(strings.TrimPrefix(line, "Pays:"))
		return true
	case strings.HasPrefix(line, "Téléphone:"):
		c.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Téléphone:"))
		return true
	case strings.HasPrefix(line, "Fax:"):
		c.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
		return true
	case strings.HasPrefix(line, "Courriel:"):
		c.Email = strings.TrimSpace(strings.TrimPrefix(line, "Courriel:"))
		return true
	case strings.HasPrefix(line, "Type:"):
		c.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
		return true
	}
	return false
}
