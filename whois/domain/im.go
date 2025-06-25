package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type IMTLDParser struct {
	parser IParser
}

func NewIMTLDParser() *IMTLDParser {
	return &IMTLDParser{
		parser: NewParser(),
	}
}

func (imw *IMTLDParser) GetName() string {
	return "im"
}

func (imw *IMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using Isle of Man-specific pattern
	if strings.Contains(rawtext, "was not found.") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	var currentContact *Contact
	var expectRegistrarName, expectContactName bool

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if imw.handleSectionHeaders(line, parsedWhois, &section, &currentContact) {
			continue
		}

		if imw.handleExpectedValues(line, parsedWhois, currentContact, &expectRegistrarName, &expectContactName) {
			continue
		}

		imw.handleSectionContent(line, section, parsedWhois, currentContact, &expectRegistrarName, &expectContactName)
	}

	return parsedWhois, nil
}

func (imw *IMTLDParser) handleSectionHeaders(line string, parsedWhois *ParsedWhois, section *string, currentContact **Contact) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name:"):
		parsedWhois.DomainName = utils.ExtractField(line, "Domain Name:")
		return true
	case line == "Domain Managers":
		*section = "registrar"
		return true
	case line == "Domain Owners / Registrant":
		*section = "registrant"
		imw.ensureContacts(parsedWhois)
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
		*currentContact = parsedWhois.Contacts.Registrant
		return true
	case line == "Administrative Contact":
		*section = "admin"
		imw.ensureContacts(parsedWhois)
		if parsedWhois.Contacts.Admin == nil {
			parsedWhois.Contacts.Admin = &Contact{}
		}
		*currentContact = parsedWhois.Contacts.Admin
		return true
	case line == "Billing Contact":
		*section = "billing"
		imw.ensureContacts(parsedWhois)
		if parsedWhois.Contacts.Billing == nil {
			parsedWhois.Contacts.Billing = &Contact{}
		}
		*currentContact = parsedWhois.Contacts.Billing
		return true
	case line == "Technical Contact":
		*section = "tech"
		imw.ensureContacts(parsedWhois)
		if parsedWhois.Contacts.Tech == nil {
			parsedWhois.Contacts.Tech = &Contact{}
		}
		*currentContact = parsedWhois.Contacts.Tech
		return true
	case line == "Domain Details":
		*section = "details"
		return true
	}
	return false
}

func (imw *IMTLDParser) ensureContacts(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
}

func (imw *IMTLDParser) handleExpectedValues(line string, parsedWhois *ParsedWhois, currentContact *Contact, expectRegistrarName, expectContactName *bool) bool {
	if *expectRegistrarName {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		if line != "Redacted" {
			parsedWhois.Registrar.Name = line
		}
		*expectRegistrarName = false
		return true
	}
	if *expectContactName && currentContact != nil {
		if line != "Redacted" {
			currentContact.Name = line
		}
		*expectContactName = false
		return true
	}
	return false
}

func (imw *IMTLDParser) handleSectionContent(line, section string, parsedWhois *ParsedWhois, currentContact *Contact, expectRegistrarName, expectContactName *bool) {
	switch section {
	case "registrar":
		imw.handleRegistrarSection(line, parsedWhois, expectRegistrarName)
	case "registrant", "admin", "billing", "tech":
		imw.handleContactSection(line, currentContact, expectContactName)
	case "details":
		imw.handleDetailsSection(line, parsedWhois)
	}
}

func (imw *IMTLDParser) handleRegistrarSection(line string, parsedWhois *ParsedWhois, expectRegistrarName *bool) {
	if strings.HasPrefix(line, "Name:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		registrarName := utils.ExtractField(line, "Name:")
		if registrarName != "Redacted" {
			parsedWhois.Registrar.Name = registrarName
		}
	} else if line == "Name" {
		*expectRegistrarName = true
	} else if parsedWhois.Registrar != nil && parsedWhois.Registrar.Name == "" && line != "" && !strings.HasPrefix(line, "Address") {
		if line != "Redacted" {
			parsedWhois.Registrar.Name = line
		}
	}
}

func (imw *IMTLDParser) handleContactSection(line string, currentContact *Contact, expectContactName *bool) {
	if imw.handleContactNameField(line, currentContact, expectContactName) {
		return
	}
	if imw.handleContactAddressField(line, currentContact) {
		return
	}
	imw.handleContactGenericField(line, currentContact)
}

func (imw *IMTLDParser) handleContactNameField(line string, currentContact *Contact, expectContactName *bool) bool {
	if strings.HasPrefix(line, "Name:") {
		if currentContact != nil {
			name := utils.ExtractField(line, "Name:")
			if !imw.isRedacted(name) {
				currentContact.Name = name
			}
		}
		return true
	}
	if line == "Name" {
		*expectContactName = true
		return true
	}
	if currentContact != nil && currentContact.Name == "" && line != "" && !strings.HasPrefix(line, "Address") {
		if !imw.isRedacted(line) {
			currentContact.Name = line
		}
		return true
	}
	return false
}

func (imw *IMTLDParser) handleContactAddressField(line string, currentContact *Contact) bool {
	if line == "Address" {
		// Address section starts, will be handled by next lines
		return true
	}
	return false
}

func (imw *IMTLDParser) handleContactGenericField(line string, currentContact *Contact) {
	if currentContact != nil && line != "" && !strings.HasPrefix(line, "Name:") && line != "Name" && line != "Address" {
		if currentContact.Street == nil {
			currentContact.Street = []string{}
		}
		if !imw.isRedacted(line) {
			currentContact.Street = append(currentContact.Street, line)
		}
	}
}

func (imw *IMTLDParser) isRedacted(value string) bool {
	return value == "Redacted"
}

func (imw *IMTLDParser) handleDetailsSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Expiry Date:") {
		date := utils.ExtractField(line, "Expiry Date:")
		if date != "" {
			parsedWhois.ExpiredDateRaw = date
		}
	} else if strings.HasPrefix(line, "Name Server:") {
		ns := utils.ExtractField(line, "Name Server:")
		if ns != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
	}
}
