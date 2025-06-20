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
		if line == "# ENGLISH" {
			inEnglish = true
			continue
		}
		if line == "# KOREAN(UTF8)" {
			inEnglish = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		if inEnglish {
			if strings.HasPrefix(line, "Domain Name") {
				parsedWhois.DomainName = getValue(line)
			} else if strings.HasPrefix(line, "Registrant Address") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Street = []string{getValue(line)}
			} else if strings.HasPrefix(line, "Registrant Zip Code") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Postal = getValue(line)
			} else if strings.HasPrefix(line, "Registrant") && !strings.HasPrefix(line, "Registrant Address") && !strings.HasPrefix(line, "Registrant Zip Code") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Registrant == nil {
					parsedWhois.Contacts.Registrant = &Contact{}
				}
				parsedWhois.Contacts.Registrant.Name = getValue(line)
			} else if strings.HasPrefix(line, "Administrative Contact(AC)") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Admin == nil {
					parsedWhois.Contacts.Admin = &Contact{}
				}
				parsedWhois.Contacts.Admin.Name = getValue(line)
			} else if strings.HasPrefix(line, "AC E-Mail") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Admin == nil {
					parsedWhois.Contacts.Admin = &Contact{}
				}
				parsedWhois.Contacts.Admin.Email = getValue(line)
			} else if strings.HasPrefix(line, "AC Phone Number") {
				if parsedWhois.Contacts == nil {
					parsedWhois.Contacts = &Contacts{}
				}
				if parsedWhois.Contacts.Admin == nil {
					parsedWhois.Contacts.Admin = &Contact{}
				}
				parsedWhois.Contacts.Admin.Phone = getValue(line)
			} else if strings.HasPrefix(line, "Registered Date") {
				parsedWhois.CreatedDateRaw = getValue(line)
			} else if strings.HasPrefix(line, "Last Updated Date") {
				parsedWhois.UpdatedDateRaw = getValue(line)
			} else if strings.HasPrefix(line, "Expiration Date") {
				parsedWhois.ExpiredDateRaw = getValue(line)
			} else if strings.HasPrefix(line, "Authorized Agency") {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				parsedWhois.Registrar.Name = getValue(line)
			} else if strings.HasPrefix(line, "DNSSEC") {
				parsedWhois.Dnssec = getValue(line)
			} else if strings.HasPrefix(line, "Host Name") {
				parsedWhois.NameServers = append(parsedWhois.NameServers, getValue(line))
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

func getValue(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}
