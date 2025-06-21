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
		if utils.SkipLine(line) {
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

func (p *SNTLDParser) parseDomainFields(line string, parsed *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Nom de domaine:"):
		parsed.DomainName = utils.ExtractField(line, "Nom de domaine:")
		return true
	case strings.HasPrefix(line, "Date de création:"):
		parsed.CreatedDateRaw = utils.ExtractField(line, "Date de création:")
		return true
	case strings.HasPrefix(line, "Dernière modification:"):
		parsed.UpdatedDateRaw = utils.ExtractField(line, "Dernière modification:")
		return true
	case strings.HasPrefix(line, "Date d'expiration:"):
		parsed.ExpiredDateRaw = utils.ExtractField(line, "Date d'expiration:")
		return true
	case strings.HasPrefix(line, "Registrar:"):
		parsed.Registrar.Name = utils.ExtractField(line, "Registrar:")
		return true
	case strings.HasPrefix(line, "Statut:"):
		status := utils.ExtractField(line, "Statut:")
		if status != "" {
			parsed.Statuses = append(parsed.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Serveur de noms:"):
		ns := utils.ExtractField(line, "Serveur de noms:")
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
		return true
	case strings.HasPrefix(line, "DNSSEC:"):
		parsed.Dnssec = utils.ExtractField(line, "DNSSEC:")
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
		c.ID = utils.ExtractField(line, "ID Contact:")
		return true
	case strings.HasPrefix(line, "Nom:"):
		c.Name = utils.ExtractField(line, "Nom:")
		return true
	case strings.HasPrefix(line, "Adresse:"):
		c.Street = append(c.Street, utils.ExtractField(line, "Adresse:"))
		return true
	case strings.HasPrefix(line, "Code postal:"):
		c.Postal = utils.ExtractField(line, "Code postal:")
		return true
	case strings.HasPrefix(line, "Ville:"):
		c.City = utils.ExtractField(line, "Ville:")
		return true
	case strings.HasPrefix(line, "Pays:"):
		c.Country = utils.ExtractField(line, "Pays:")
		return true
	case strings.HasPrefix(line, "Téléphone:"):
		c.Phone = utils.ExtractField(line, "Téléphone:")
		return true
	case strings.HasPrefix(line, "Fax:"):
		c.Fax = utils.ExtractField(line, "Fax:")
		return true
	case strings.HasPrefix(line, "Courriel:"):
		c.Email = utils.ExtractField(line, "Courriel:")
		return true
	case strings.HasPrefix(line, "Type:"):
		c.Organization = utils.ExtractField(line, "Type:")
		return true
	}
	return false
}
