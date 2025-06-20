package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type KRTLDParser struct {
	parser IParser
}

func NewKRTLDParser() *KRTLDParser {
	return &KRTLDParser{
		parser: NewParser(),
	}
}

func (krw *KRTLDParser) GetName() string {
	return "kr"
}

func (krw *KRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Detect unregistered/restricted domain
	for _, line := range lines {
		if strings.Contains(line, "restricted to specifically qualified registrants") ||
			strings.Contains(line, "등록자격이 제한된 도메인이름입니다") {
			parsedWhois.Statuses = []string{"free"}
			return parsedWhois, nil
		}
	}

	var inEnglish bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if krw.handleSectionChange(line, &inEnglish) {
			continue
		}
		if krw.skipLine(line) {
			continue
		}
		if inEnglish {
			if krw.parseDomainFields(line, parsedWhois) {
				continue
			}
			if krw.parseContactFields(line, parsedWhois) {
				continue
			}
		}
	}

	// Convert date formats using standardized approach
	if parsedWhois.CreatedDateRaw != "" {
		parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
	}
	if parsedWhois.UpdatedDateRaw != "" {
		parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
	}
	if parsedWhois.ExpiredDateRaw != "" {
		parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
	}

	return parsedWhois, nil
}

func (krw *KRTLDParser) handleSectionChange(line string, inEnglish *bool) bool {
	switch line {
	case "# ENGLISH":
		*inEnglish = true
		return true
	case "# KOREAN(UTF8)":
		*inEnglish = false
		return true
	}
	return false
}

func (krw *KRTLDParser) skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-")
}

func (krw *KRTLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain Name"):
		parsedWhois.DomainName = getValue(line)
		return true
	case strings.HasPrefix(line, "Registered Date"):
		parsedWhois.CreatedDateRaw = getValue(line)
		return true
	case strings.HasPrefix(line, "Last Updated Date"):
		parsedWhois.UpdatedDateRaw = getValue(line)
		return true
	case strings.HasPrefix(line, "Expiration Date"):
		parsedWhois.ExpiredDateRaw = getValue(line)
		return true
	case strings.HasPrefix(line, "Authorized Agency"):
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = getValue(line)
		return true
	case strings.HasPrefix(line, "DNSSEC"):
		parsedWhois.Dnssec = getValue(line)
		return true
	case strings.HasPrefix(line, "Host Name"):
		parsedWhois.NameServers = append(parsedWhois.NameServers, getValue(line))
		return true
	}
	return false
}

func (krw *KRTLDParser) parseContactFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Registrant Address"):
		krw.ensureContact(parsedWhois, "registrant")
		parsedWhois.Contacts.Registrant.Street = []string{getValue(line)}
		return true
	case strings.HasPrefix(line, "Registrant Zip Code"):
		krw.ensureContact(parsedWhois, "registrant")
		parsedWhois.Contacts.Registrant.Postal = getValue(line)
		return true
	case strings.HasPrefix(line, "Registrant") &&
		!strings.HasPrefix(line, "Registrant Address") &&
		!strings.HasPrefix(line, "Registrant Zip Code"):
		krw.ensureContact(parsedWhois, "registrant")
		parsedWhois.Contacts.Registrant.Name = getValue(line)
		return true
	case strings.HasPrefix(line, "Administrative Contact(AC)"):
		krw.ensureContact(parsedWhois, "admin")
		parsedWhois.Contacts.Admin.Name = getValue(line)
		return true
	case strings.HasPrefix(line, "AC E-Mail"):
		krw.ensureContact(parsedWhois, "admin")
		parsedWhois.Contacts.Admin.Email = getValue(line)
		return true
	case strings.HasPrefix(line, "AC Phone Number"):
		krw.ensureContact(parsedWhois, "admin")
		parsedWhois.Contacts.Admin.Phone = getValue(line)
		return true
	}
	return false
}

func (krw *KRTLDParser) ensureContact(parsedWhois *ParsedWhois, contactType string) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	switch contactType {
	case "registrant":
		if parsedWhois.Contacts.Registrant == nil {
			parsedWhois.Contacts.Registrant = &Contact{}
		}
	case "admin":
		if parsedWhois.Contacts.Admin == nil {
			parsedWhois.Contacts.Admin = &Contact{}
		}
	}
}

func getValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
