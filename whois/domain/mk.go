package domain

import (
	"strings"
)

type MKTLDParser struct {
	parser IParser
}

func NewMKTLDParser() *MKTLDParser {
	return &MKTLDParser{
		parser: NewParser(),
	}
}

func (mkw *MKTLDParser) GetName() string {
	return "mk"
}

func (mkw *MKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "no entries found") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	var contactMap = make(map[string]*Contact)
	var nssetMap = make(map[string][]string)
	var domainFields = make(map[string]string)

	// First pass: collect top-level fields from the first non-comment, non-blank line until the next blank line
	inDomainBlock := false
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !inDomainBlock {
			if line == "" || strings.HasPrefix(line, "%") {
				continue
			}
			inDomainBlock = true
		}
		if line == "" {
			break // Stop at first blank line after domain block
		}
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		topLevelKeys := map[string]bool{"domain": true, "registrar": true, "registered": true, "changed": true, "expire": true, "registrant": true, "admin-c": true, "nsset": true}
		if topLevelKeys[key] {
			domainFields[key] = val
		}
	}

	// Second pass: process sections
	var currentSection string
	var currentHandle string
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "contact" {
			currentSection = "contact"
			currentHandle = strings.TrimSpace(val)
			contactMap[currentHandle] = &Contact{}
			continue
		} else if key == "nsset" {
			currentSection = "nsset"
			currentHandle = strings.TrimSpace(val)
			nssetMap[currentHandle] = []string{}
			continue
		}
		if currentSection == "contact" {
			c := contactMap[currentHandle]
			switch key {
			case "org":
				c.Organization = val
			case "name":
				c.Name = val
			case "address":
				c.Street = append(c.Street, val)
			case "phone":
				c.Phone = val
			case "fax-no":
				c.Fax = val
			case "e-mail":
				c.Email = val
			}
		} else if currentSection == "nsset" {
			if key == "nserver" {
				nssetMap[currentHandle] = append(nssetMap[currentHandle], val)
			}
		}
	}

	// Assign domain fields
	if v, ok := domainFields["domain"]; ok {
		parsedWhois.DomainName = v
	}
	if v, ok := domainFields["registrar"]; ok {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = v
	}
	if v, ok := domainFields["registered"]; ok {
		parsedWhois.CreatedDateRaw = v
	}
	if v, ok := domainFields["changed"]; ok {
		parsedWhois.UpdatedDateRaw = v
	}
	if v, ok := domainFields["expire"]; ok {
		parsedWhois.ExpiredDateRaw = v
	}
	// Assign contacts
	if v, ok := domainFields["registrant"]; ok {
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if c, ok := contactMap[strings.TrimSpace(v)]; ok {
			parsedWhois.Contacts.Registrant = c
		}
	}
	if v, ok := domainFields["admin-c"]; ok {
		if parsedWhois.Contacts == nil {
			parsedWhois.Contacts = &Contacts{}
		}
		if c, ok := contactMap[strings.TrimSpace(v)]; ok {
			parsedWhois.Contacts.Admin = c
		}
	}
	// Assign nameservers
	if v, ok := domainFields["nsset"]; ok {
		v = strings.TrimSpace(v)
		if nsservers, ok := nssetMap[v]; ok {
			parsedWhois.NameServers = nsservers
		}
	}

	return parsedWhois, nil
}

func getMKValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
