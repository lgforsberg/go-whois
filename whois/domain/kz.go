package domain

import (
	"strings"
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
		parsedWhois.Statuses = []string{"free"}
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
		parsedWhois.DomainName = getKZValue(line)
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
		parsedWhois.CreatedDateRaw = getKZValue(line)
		return true
	case strings.HasPrefix(line, "Last modified"):
		parsedWhois.UpdatedDateRaw = getKZValue(line)
		return true
	case strings.HasPrefix(line, "Domain status"):
		status := getKZValue(line)
		if status != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		}
		return true
	case strings.HasPrefix(line, "Current Registar"):
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = getKZValue(line)
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
		parsedWhois.Contacts.Registrant.Name = getKZValue(line)
	} else if strings.HasPrefix(line, "Organization Name") {
		parsedWhois.Contacts.Registrant.Organization = getKZValue(line)
	} else if strings.HasPrefix(line, "Street Address") {
		parsedWhois.Contacts.Registrant.Street = []string{getKZValue(line)}
	} else if strings.HasPrefix(line, "City") {
		parsedWhois.Contacts.Registrant.City = getKZValue(line)
	} else if strings.HasPrefix(line, "State") {
		parsedWhois.Contacts.Registrant.State = getKZValue(line)
	} else if strings.HasPrefix(line, "Postal Code") {
		parsedWhois.Contacts.Registrant.Postal = getKZValue(line)
	} else if strings.HasPrefix(line, "Country") {
		parsedWhois.Contacts.Registrant.Country = getKZValue(line)
	}
}

func (kzw *KZTLDParser) handleAdminSection(line string, parsedWhois *ParsedWhois) {
	kzw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Admin == nil {
		parsedWhois.Contacts.Admin = &Contact{}
	}
	if strings.HasPrefix(line, "Name") {
		parsedWhois.Contacts.Admin.Name = getKZValue(line)
	} else if strings.HasPrefix(line, "Phone Number") {
		parsedWhois.Contacts.Admin.Phone = getKZValue(line)
	} else if strings.HasPrefix(line, "Fax Number") {
		parsedWhois.Contacts.Admin.Fax = getKZValue(line)
	} else if strings.HasPrefix(line, "Email Address") {
		parsedWhois.Contacts.Admin.Email = getKZValue(line)
	}
}

func (kzw *KZTLDParser) handleNameserversSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Primary server") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, getKZValue(line))
	} else if strings.HasPrefix(line, "Secondary server") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, getKZValue(line))
	}
}

func getKZValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
