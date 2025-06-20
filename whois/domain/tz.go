package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type TZParser struct{}

type TZTLDParser struct {
	parser IParser
}

func NewTZTLDParser() *TZTLDParser {
	return &TZTLDParser{
		parser: NewParser(),
	}
}

func (p *TZTLDParser) GetName() string {
	return "tz"
}

func (p *TZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	if strings.Contains(rawtext, "%ERROR:101: no entries found") || strings.Contains(rawtext, "% No entries found.") {
		return parsed, nil
	}

	lines := strings.Split(rawtext, "\n")
	var (
		domain, registrant, registrar, nsset, adminC string
		created, expire                              string
		contactSections                              = map[string][]string{}
		nssetSections                                = map[string][]string{}
	)

	// First pass: collect main fields and section start indices
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "domain:") {
			domain = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
			continue
		}
		if strings.HasPrefix(line, "registrant:") {
			registrant = strings.TrimSpace(strings.TrimPrefix(line, "registrant:"))
			continue
		}
		if strings.HasPrefix(line, "admin-c:") {
			if adminC == "" {
				adminC = strings.TrimSpace(strings.TrimPrefix(line, "admin-c:"))
			} // Only first admin-c for now
			continue
		}
		if strings.HasPrefix(line, "nsset:") && domain != "" {
			// Only set nsset from the main record (before any contact/nsset sections)
			if nsset == "" {
				nsset = strings.TrimSpace(strings.TrimPrefix(line, "nsset:"))
			}
			continue
		}
		if strings.HasPrefix(line, "registrar:") {
			registrar = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
			continue
		}
		if strings.HasPrefix(line, "registered:") {
			created = strings.TrimSpace(strings.TrimPrefix(line, "registered:"))
			continue
		}
		if strings.HasPrefix(line, "expire:") {
			expire = strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
			continue
		}
	}

	// Second pass: collect contact and nsset sections
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "contact:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "contact:"))
			var section []string
			section = append(section, line)
			for j := i + 1; j < len(lines); j++ {
				l := strings.TrimSpace(lines[j])
				if l == "" || strings.HasPrefix(l, "%") || strings.HasPrefix(l, "contact:") || strings.HasPrefix(l, "nsset:") {
					break
				}
				section = append(section, l)
			}
			contactSections[id] = section
			continue
		}
		if strings.HasPrefix(line, "nsset:") {
			id := strings.TrimSpace(strings.TrimPrefix(line, "nsset:"))
			var section []string
			section = append(section, line)
			for j := i + 1; j < len(lines); j++ {
				l := strings.TrimSpace(lines[j])
				if l == "" || strings.HasPrefix(l, "%") || strings.HasPrefix(l, "contact:") || strings.HasPrefix(l, "nsset:") {
					break
				}
				section = append(section, l)
			}
			nssetSections[id] = section
			continue
		}
	}

	parsed.DomainName = domain
	parsed.CreatedDateRaw = created
	parsed.ExpiredDateRaw = expire
	parsed.Registrar.Name = registrar

	// Parse contacts
	if registrant != "" {
		parsed.Contacts.Registrant = parseTZContact(contactSections[registrant])
	}
	if adminC != "" {
		parsed.Contacts.Admin = parseTZContact(contactSections[adminC])
	}

	// Parse nameservers from nsset
	if nsset != "" {
		parsed.NameServers = parseTZNameServers(nssetSections[nsset])
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

func parseTZContact(lines []string) *Contact {
	if len(lines) == 0 {
		return nil
	}
	c := &Contact{}
	for _, line := range lines {
		if strings.HasPrefix(line, "contact:") {
			c.ID = strings.TrimSpace(strings.TrimPrefix(line, "contact:"))
			continue
		}
		if strings.HasPrefix(line, "registrar:") {
			c.Organization = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
			continue
		}
	}
	return c
}

func parseTZNameServers(lines []string) []string {
	ns := []string{}
	for _, line := range lines {
		if strings.HasPrefix(line, "nserver:") {
			n := strings.TrimSpace(strings.TrimPrefix(line, "nserver:"))
			if n != "" {
				ns = append(ns, n)
			}
		}
	}
	return ns
}
