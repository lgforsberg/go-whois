package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TGTLDParser struct {
	parser IParser
}

func NewTGTLDParser() *TGTLDParser {
	return &TGTLDParser{
		parser: NewParser(),
	}
}

func (p *TGTLDParser) GetName() string {
	return "tg"
}

func (p *TGTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "NO OBJECT FOUND!") {
		return parsed, nil
	}

	// Split into sections
	sections := strings.Split(rawtext, "----------------------------------------")

	// Process the first section (they all contain the same domain info)
	if len(sections) > 0 {
		section := sections[0]
		lines := strings.Split(section, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "This is") || strings.HasPrefix(line, "Java Whois") ||
				strings.HasPrefix(line, "All rights") || strings.HasPrefix(line, "Copyright") {
				continue
			}

			if strings.HasPrefix(line, "Domain:") {
				parsed.DomainName = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "Registrar:") {
				parsed.Registrar.Name = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "Activation:") {
				parsed.CreatedDateRaw = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "Expiration:") {
				parsed.ExpiredDateRaw = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "Status:") {
				status := extractValue(line)
				if status != "" {
					parsed.Statuses = append(parsed.Statuses, status)
				}
				continue
			}
			if strings.HasPrefix(line, "Name Server (DB):") {
				ns := extractValue(line)
				if ns != "" {
					parsed.NameServers = append(parsed.NameServers, ns)
				}
				continue
			}
		}
	}

	// Process contact information from all sections
	var owner, admin, tech Contact

	for _, section := range sections {
		if strings.TrimSpace(section) == "" {
			continue
		}

		lines := strings.Split(section, "\n")
		var currentContact *Contact
		var contactType string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "Contact Type:") {
				contactType = extractValue(line)
				switch contactType {
				case "owner":
					currentContact = &owner
				case "administrative":
					currentContact = &admin
				case "technical":
					currentContact = &tech
				}
				continue
			}

			if currentContact == nil {
				continue
			}

			if strings.HasPrefix(line, "Last Name:") {
				currentContact.Name = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "First Name:") {
				firstName := extractValue(line)
				if currentContact.Name != "" {
					currentContact.Name = firstName + " " + currentContact.Name
				} else {
					currentContact.Name = firstName
				}
				continue
			}
			if strings.HasPrefix(line, "Address:") {
				address := extractValue(line)
				currentContact.Street = append(currentContact.Street, address)
				continue
			}
			if strings.HasPrefix(line, "Tel:") {
				currentContact.Phone = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "Fax:") {
				currentContact.Fax = extractValue(line)
				continue
			}
			if strings.HasPrefix(line, "e-mail:") {
				currentContact.Email = extractValue(line)
				continue
			}
			// Handle address continuation lines
			if currentContact.Street != nil && len(currentContact.Street) > 0 &&
				!strings.Contains(line, ":") && line != "" {
				currentContact.Street = append(currentContact.Street, line)
			}
		}
	}

	if owner.Name != "" {
		parsed.Contacts.Registrant = &owner
	}
	if admin.Name != "" {
		parsed.Contacts.Admin = &admin
	}
	if tech.Name != "" {
		parsed.Contacts.Tech = &tech
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

// extractValue extracts the value after dots for alignment
func extractValue(line string) string {
	// Find the colon
	colonIndex := strings.Index(line, ":")
	if colonIndex == -1 {
		return strings.TrimSpace(line)
	}

	// Start after the colon
	start := colonIndex + 1

	// Find the first non-dot character after the colon
	for start < len(line) && line[start] == '.' {
		start++
	}

	// Extract everything from the first non-dot character
	if start < len(line) {
		return strings.TrimSpace(line[start:])
	}

	return ""
}
