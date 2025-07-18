package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type KZTLDParser struct {
	parser IParser
}

func NewKZTLDParser() *KZTLDParser {
	return &KZTLDParser{
		parser: NewParser(),
	}
}

func (kzw *KZTLDParser) GetName() string {
	return "kz"
}

func (kzw *KZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "Nothing found for this query") {
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	var section string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Whois Server") || strings.HasPrefix(line, "This server") {
			continue
		}

		if kzw.handleSectionHeaders(line, parsedWhois, &section) {
			continue
		}

		kzw.handleSectionContent(line, section, parsedWhois)
	}

	return parsedWhois, nil
}

func (kzw *KZTLDParser) handleSectionHeaders(line string, parsedWhois *ParsedWhois, section *string) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name"):
		parsedWhois.DomainName = utils.ExtractValue(line)
		return true
	case line == "Organization Using Domain Name":
		*section = "organization"
		return true
	case line == "Administrative Contact/Agent":
		*section = "admin"
		kzw.ensureContacts(parsedWhois)
		if parsedWhois.Contacts.Admin == nil {
			parsedWhois.Contacts.Admin = &Contact{}
		}
		return true
	case line == "Nameserver in listed order":
		*section = "nameservers"
		return true
	case strings.HasPrefix(line, "Domain created"):
		parsedWhois.CreatedDateRaw = utils.ExtractValue(line)
		return true
	case strings.HasPrefix(line, "Last modified"):
		parsedWhois.UpdatedDateRaw = utils.ExtractValue(line)
		return true
	case strings.HasPrefix(line, "Domain status"):
		status := utils.ExtractValue(line)
		if status != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Current Registar"):
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = utils.ExtractValue(line)
		return true
	}
	return false
}

func (kzw *KZTLDParser) ensureContacts(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
}

func (kzw *KZTLDParser) handleSectionContent(line, section string, parsedWhois *ParsedWhois) {
	switch section {
	case "organization":
		kzw.handleOrganizationSection(line, parsedWhois)
	case "admin":
		kzw.handleAdminSection(line, parsedWhois)
	case "nameservers":
		kzw.handleNameserversSection(line, parsedWhois)
	}
}

func (kzw *KZTLDParser) handleOrganizationSection(line string, parsedWhois *ParsedWhois) {
	kzw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}
	if strings.HasPrefix(line, "Name") {
		parsedWhois.Contacts.Registrant.Name = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Organization Name") {
		parsedWhois.Contacts.Registrant.Organization = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Street Address") {
		parsedWhois.Contacts.Registrant.Street = []string{utils.ExtractValue(line)}
	} else if strings.HasPrefix(line, "City") {
		parsedWhois.Contacts.Registrant.City = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "State") {
		parsedWhois.Contacts.Registrant.State = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Postal Code") {
		parsedWhois.Contacts.Registrant.Postal = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Country") {
		parsedWhois.Contacts.Registrant.Country = utils.ExtractValue(line)
	}
}

func (kzw *KZTLDParser) handleAdminSection(line string, parsedWhois *ParsedWhois) {
	kzw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Admin == nil {
		parsedWhois.Contacts.Admin = &Contact{}
	}
	if strings.HasPrefix(line, "Name") {
		parsedWhois.Contacts.Admin.Name = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Phone Number") {
		parsedWhois.Contacts.Admin.Phone = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Fax Number") {
		parsedWhois.Contacts.Admin.Fax = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Email Address") {
		parsedWhois.Contacts.Admin.Email = utils.ExtractValue(line)
	}
}

func (kzw *KZTLDParser) handleNameserversSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Primary server") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, utils.ExtractValue(line))
	} else if strings.HasPrefix(line, "Secondary server") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, utils.ExtractValue(line))
	}
}
