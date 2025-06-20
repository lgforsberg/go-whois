package domain

import (
	"strings"
)

type HKTLDParser struct {
	parser IParser
}

func NewHKTLDParser() *HKTLDParser {
	return &HKTLDParser{
		parser: NewParser(),
	}
}

func (hkw *HKTLDParser) GetName() string {
	return "hk"
}

func (hkw *HKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if strings.Contains(rawtext, "This domain is currently not available for registration") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	var currentContact *Contact

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		if hkw.handleSectionHeaders(trimmed, parsedWhois, &section, &currentContact) {
			continue
		}

		hkw.handleSectionContent(trimmed, section, parsedWhois, currentContact)
	}

	return parsedWhois, nil
}

func (hkw *HKTLDParser) handleSectionHeaders(trimmed string, parsedWhois *ParsedWhois, section *string, currentContact **Contact) bool {
	switch {
	case strings.HasPrefix(trimmed, "Domain Name:"):
		return hkw.handleDomainHeader(trimmed, parsedWhois, section)
	case strings.HasPrefix(trimmed, "Domain Status:"):
		return hkw.handleStatusHeader(trimmed, parsedWhois, section)
	case strings.HasPrefix(trimmed, "DNSSEC:"):
		return hkw.handleDnssecHeader(trimmed, parsedWhois, section)
	case strings.HasPrefix(trimmed, "Registrar Name:"):
		return hkw.handleRegistrarHeader(trimmed, parsedWhois, section)
	case strings.HasPrefix(trimmed, "Registrar Contact Information:"):
		return hkw.handleRegistrarContactHeader(section)
	case strings.HasPrefix(trimmed, "Registrant Contact Information:"):
		return hkw.handleRegistrantHeader(parsedWhois, section, currentContact)
	case strings.HasPrefix(trimmed, "Administrative Contact Information:"):
		return hkw.handleAdminHeader(parsedWhois, section, currentContact)
	case strings.HasPrefix(trimmed, "Technical Contact Information:"):
		return hkw.handleTechHeader(parsedWhois, section, currentContact)
	case strings.HasPrefix(trimmed, "Name Servers Information:"):
		return hkw.handleNameserversHeader(section)
	case strings.HasPrefix(trimmed, "Status Information:"):
		return hkw.handleStatusInfoHeader(section)
	}
	return false
}

func (hkw *HKTLDParser) handleDomainHeader(trimmed string, parsedWhois *ParsedWhois, section *string) bool {
	*section = "domain"
	parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Name:"))
	return true
}

func (hkw *HKTLDParser) handleStatusHeader(trimmed string, parsedWhois *ParsedWhois, section *string) bool {
	*section = "status"
	status := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Status:"))
	if status != "" {
		parsedWhois.Statuses = append(parsedWhois.Statuses, status)
	}
	return true
}

func (hkw *HKTLDParser) handleDnssecHeader(trimmed string, parsedWhois *ParsedWhois, section *string) bool {
	*section = "dnssec"
	parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(trimmed, "DNSSEC:"))
	return true
}

func (hkw *HKTLDParser) handleRegistrarHeader(trimmed string, parsedWhois *ParsedWhois, section *string) bool {
	*section = "registrar"
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Registrar Name:"))
	return true
}

func (hkw *HKTLDParser) handleRegistrarContactHeader(section *string) bool {
	*section = "registrar_contact"
	return true
}

func (hkw *HKTLDParser) handleRegistrantHeader(parsedWhois *ParsedWhois, section *string, currentContact **Contact) bool {
	*section = "registrant"
	hkw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}
	*currentContact = parsedWhois.Contacts.Registrant
	return true
}

func (hkw *HKTLDParser) handleAdminHeader(parsedWhois *ParsedWhois, section *string, currentContact **Contact) bool {
	*section = "admin"
	hkw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Admin == nil {
		parsedWhois.Contacts.Admin = &Contact{}
	}
	*currentContact = parsedWhois.Contacts.Admin
	return true
}

func (hkw *HKTLDParser) handleTechHeader(parsedWhois *ParsedWhois, section *string, currentContact **Contact) bool {
	*section = "tech"
	hkw.ensureContacts(parsedWhois)
	if parsedWhois.Contacts.Tech == nil {
		parsedWhois.Contacts.Tech = &Contact{}
	}
	*currentContact = parsedWhois.Contacts.Tech
	return true
}

func (hkw *HKTLDParser) handleNameserversHeader(section *string) bool {
	*section = "nameservers"
	return true
}

func (hkw *HKTLDParser) handleStatusInfoHeader(section *string) bool {
	*section = "status_info"
	return true
}

func (hkw *HKTLDParser) ensureContacts(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
}

func (hkw *HKTLDParser) handleSectionContent(trimmed, section string, parsedWhois *ParsedWhois, currentContact *Contact) {
	switch section {
	case "registrar_contact":
		hkw.handleRegistrarContact(trimmed, parsedWhois)
	case "registrant":
		hkw.handleRegistrantSection(trimmed, parsedWhois, currentContact)
	case "admin", "tech":
		hkw.handleAdminTechSection(trimmed, currentContact)
	case "nameservers":
		hkw.handleNameservers(trimmed, parsedWhois)
	case "status_info":
		hkw.handleStatusInfo(trimmed, parsedWhois)
	}
}

func (hkw *HKTLDParser) handleRegistrarContact(trimmed string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(trimmed, "Email:") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.AbuseContactEmail = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
	}
}

func (hkw *HKTLDParser) handleRegistrantSection(trimmed string, parsedWhois *ParsedWhois, currentContact *Contact) {
	switch {
	case strings.HasPrefix(trimmed, "Company English Name"):
		if currentContact != nil {
			currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(trimmed, "Company English Name (It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents):"))
		}
	case strings.HasPrefix(trimmed, "Address:"):
		if currentContact != nil {
			address := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
			if address != "" {
				currentContact.Street = append(currentContact.Street, address)
			}
		}
	case strings.HasPrefix(trimmed, "Country:"):
		if currentContact != nil {
			currentContact.Country = strings.TrimSpace(strings.TrimPrefix(trimmed, "Country:"))
		}
	case strings.HasPrefix(trimmed, "Email:"):
		if currentContact != nil {
			currentContact.Email = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
		}
	case strings.HasPrefix(trimmed, "Domain Name Commencement Date:"):
		date := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Name Commencement Date:"))
		if date != "" {
			parsedWhois.CreatedDateRaw = date
		}
	case strings.HasPrefix(trimmed, "Expiry Date:"):
		date := strings.TrimSpace(strings.TrimPrefix(trimmed, "Expiry Date:"))
		if date != "" {
			parsedWhois.ExpiredDateRaw = date
		}
	}
}

func (hkw *HKTLDParser) handleAdminTechSection(trimmed string, currentContact *Contact) {
	if hkw.handleNameFields(trimmed, currentContact) {
		return
	}
	if hkw.handleOrganizationField(trimmed, currentContact) {
		return
	}
	if hkw.handleAddressField(trimmed, currentContact) {
		return
	}
	if hkw.handleCountryField(trimmed, currentContact) {
		return
	}
	if hkw.handlePhoneField(trimmed, currentContact) {
		return
	}
	if hkw.handleFaxField(trimmed, currentContact) {
		return
	}
	hkw.handleEmailField(trimmed, currentContact)
}

func (hkw *HKTLDParser) handleNameFields(trimmed string, currentContact *Contact) bool {
	switch {
	case strings.HasPrefix(trimmed, "Given name:"):
		if currentContact != nil {
			currentContact.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Given name:"))
		}
		return true
	case strings.HasPrefix(trimmed, "Family name:"):
		if currentContact != nil && currentContact.Name != "" {
			currentContact.Name += " " + strings.TrimSpace(strings.TrimPrefix(trimmed, "Family name:"))
		} else if currentContact != nil {
			currentContact.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "Family name:"))
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handleOrganizationField(trimmed string, currentContact *Contact) bool {
	if strings.HasPrefix(trimmed, "Company name:") {
		if currentContact != nil {
			currentContact.Organization = strings.TrimSpace(strings.TrimPrefix(trimmed, "Company name:"))
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handleAddressField(trimmed string, currentContact *Contact) bool {
	if strings.HasPrefix(trimmed, "Address:") {
		if currentContact != nil {
			address := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
			if address != "" {
				currentContact.Street = append(currentContact.Street, address)
			}
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handleCountryField(trimmed string, currentContact *Contact) bool {
	if strings.HasPrefix(trimmed, "Country:") {
		if currentContact != nil {
			currentContact.Country = strings.TrimSpace(strings.TrimPrefix(trimmed, "Country:"))
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handlePhoneField(trimmed string, currentContact *Contact) bool {
	if strings.HasPrefix(trimmed, "Phone:") {
		if currentContact != nil {
			currentContact.Phone = strings.TrimSpace(strings.TrimPrefix(trimmed, "Phone:"))
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handleFaxField(trimmed string, currentContact *Contact) bool {
	if strings.HasPrefix(trimmed, "Fax:") {
		if currentContact != nil {
			currentContact.Fax = strings.TrimSpace(strings.TrimPrefix(trimmed, "Fax:"))
		}
		return true
	}
	return false
}

func (hkw *HKTLDParser) handleEmailField(trimmed string, currentContact *Contact) {
	if strings.HasPrefix(trimmed, "Email:") {
		if currentContact != nil {
			currentContact.Email = strings.TrimSpace(strings.TrimPrefix(trimmed, "Email:"))
		}
	}
}

func (hkw *HKTLDParser) handleNameservers(trimmed string, parsedWhois *ParsedWhois) {
	if trimmed != "" && !strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "WHOIS") && !strings.Contains(trimmed, "Copyright") && !strings.Contains(trimmed, "Terms") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, trimmed)
	}
}

func (hkw *HKTLDParser) handleStatusInfo(trimmed string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(trimmed, "Domain Prohibit Status:") {
		status := strings.TrimSpace(strings.TrimPrefix(trimmed, "Domain Prohibit Status:"))
		if status != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, status)
		}
	}
}
