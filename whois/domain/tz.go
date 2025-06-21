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

	mainFields := p.parseMainFields(lines)
	contactSections := p.collectContactSections(lines)
	nssetSections := p.collectNssetSections(lines)

	parsed.DomainName = mainFields.domain
	parsed.CreatedDateRaw = mainFields.created
	parsed.ExpiredDateRaw = mainFields.expire
	parsed.Registrar.Name = mainFields.registrar

	// Parse contacts
	if mainFields.registrant != "" {
		parsed.Contacts.Registrant = parseTZContact(contactSections[mainFields.registrant])
	}
	if mainFields.adminC != "" {
		parsed.Contacts.Admin = parseTZContact(contactSections[mainFields.adminC])
	}

	// Parse nameservers from nsset
	if mainFields.nsset != "" {
		parsed.NameServers = parseTZNameServers(nssetSections[mainFields.nsset])
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}

type tzMainFields struct {
	domain, registrant, registrar, nsset, adminC string
	created, expire                              string
}

func (p *TZTLDParser) parseMainFields(lines []string) tzMainFields {
	var fields tzMainFields
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if utils.SkipLine(line) {
			continue
		}
		if strings.HasPrefix(line, "domain:") {
			fields.domain = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
			continue
		}
		if strings.HasPrefix(line, "registrant:") {
			fields.registrant = strings.TrimSpace(strings.TrimPrefix(line, "registrant:"))
			continue
		}
		if strings.HasPrefix(line, "admin-c:") {
			if fields.adminC == "" {
				fields.adminC = strings.TrimSpace(strings.TrimPrefix(line, "admin-c:"))
			}
			continue
		}
		if strings.HasPrefix(line, "nsset:") && fields.domain != "" {
			if fields.nsset == "" {
				fields.nsset = strings.TrimSpace(strings.TrimPrefix(line, "nsset:"))
			}
			continue
		}
		if strings.HasPrefix(line, "registrar:") {
			fields.registrar = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
			continue
		}
		if strings.HasPrefix(line, "registered:") {
			fields.created = strings.TrimSpace(strings.TrimPrefix(line, "registered:"))
			continue
		}
		if strings.HasPrefix(line, "expire:") {
			fields.expire = strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
			continue
		}
	}
	return fields
}

func (p *TZTLDParser) collectContactSections(lines []string) map[string][]string {
	contactSections := map[string][]string{}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if utils.SkipLine(line) {
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
		}
	}
	return contactSections
}

func (p *TZTLDParser) collectNssetSections(lines []string) map[string][]string {
	nssetSections := map[string][]string{}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if utils.SkipLine(line) {
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
		}
	}
	return nssetSections
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
