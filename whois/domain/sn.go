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
		if line == "" || strings.HasPrefix(line, "=") || strings.HasPrefix(line, ">>>") {
			continue
		}
		if strings.HasPrefix(line, "Nom de domaine:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Nom de domaine:"))
			continue
		}
		if strings.HasPrefix(line, "Date de création:") {
			parsed.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Date de création:"))
			continue
		}
		if strings.HasPrefix(line, "Dernière modification:") {
			parsed.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Dernière modification:"))
			continue
		}
		if strings.HasPrefix(line, "Date d'expiration:") {
			parsed.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Date d'expiration:"))
			continue
		}
		if strings.HasPrefix(line, "Registrar:") {
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
			continue
		}
		if strings.HasPrefix(line, "Statut:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Statut:"))
			if status != "" {
				parsed.Statuses = append(parsed.Statuses, status)
			}
			continue
		}
		if strings.HasPrefix(line, "Serveur de noms:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Serveur de noms:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
			continue
		}
		if strings.HasPrefix(line, "DNSSEC:") {
			parsed.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
			continue
		}
		if line == "[BILLING_C]" {
			section = "billing"
			continue
		}
		if line == "[TECH_C]" {
			section = "tech"
			continue
		}
		if line == "[HOLDER]" {
			section = "holder"
			continue
		}
		if line == "[ADMIN_C]" {
			section = "admin"
			continue
		}

		// Parse contact sections
		var c *Contact
		if section == "billing" {
			c = &billing
		} else if section == "tech" {
			c = &tech
		} else if section == "holder" {
			c = &holder
		} else if section == "admin" {
			c = &admin
		} else {
			continue
		}

		if strings.HasPrefix(line, "ID Contact:") {
			c.ID = strings.TrimSpace(strings.TrimPrefix(line, "ID Contact:"))
			continue
		}
		if strings.HasPrefix(line, "Nom:") {
			c.Name = strings.TrimSpace(strings.TrimPrefix(line, "Nom:"))
			continue
		}
		if strings.HasPrefix(line, "Adresse:") {
			c.Street = append(c.Street, strings.TrimSpace(strings.TrimPrefix(line, "Adresse:")))
			continue
		}
		if strings.HasPrefix(line, "Code postal:") {
			c.Postal = strings.TrimSpace(strings.TrimPrefix(line, "Code postal:"))
			continue
		}
		if strings.HasPrefix(line, "Ville:") {
			c.City = strings.TrimSpace(strings.TrimPrefix(line, "Ville:"))
			continue
		}
		if strings.HasPrefix(line, "Pays:") {
			c.Country = strings.TrimSpace(strings.TrimPrefix(line, "Pays:"))
			continue
		}
		if strings.HasPrefix(line, "Téléphone:") {
			c.Phone = strings.TrimSpace(strings.TrimPrefix(line, "Téléphone:"))
			continue
		}
		if strings.HasPrefix(line, "Fax:") {
			c.Fax = strings.TrimSpace(strings.TrimPrefix(line, "Fax:"))
			continue
		}
		if strings.HasPrefix(line, "Courriel:") {
			c.Email = strings.TrimSpace(strings.TrimPrefix(line, "Courriel:"))
			continue
		}
		if strings.HasPrefix(line, "Type:") {
			c.Organization = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
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
