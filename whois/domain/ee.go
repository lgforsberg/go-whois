package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const eeTimeFmt = "2006-01-02 15:04:05 -07:00"

// EETLDParser parses .ee whois data
// Handles sections: Domain, Registrant, Administrative contact, Technical contact, Registrar, Name servers

type EETLDParser struct {
	parser IParser
}

func NewEETLDParser() *EETLDParser {
	return &EETLDParser{
		parser: NewParser(),
	}
}

func (eew *EETLDParser) GetName() string {
	return "ee"
}

func (eew *EETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	if strings.Contains(rawtext, "Domain not found") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var section string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if utils.SkipLine(line) {
			continue
		}
		if eew.handleSectionChange(line, &section) {
			continue
		}
		eew.parseFieldsBySection(line, section, parsedWhois)
	}

	return parsedWhois, nil
}

func (eew *EETLDParser) handleSectionChange(line string, section *string) bool {
	switch line {
	case "Domain:", "Registrant:", "Administrative contact:", "Technical contact:", "Registrar:", "Name servers:":
		*section = line
		return true
	}
	return false
}

func (eew *EETLDParser) parseFieldsBySection(line, section string, parsedWhois *ParsedWhois) {
	switch section {
	case "Domain:":
		eew.parseDomainFields(line, parsedWhois)
	case "Registrant:":
		eew.parseContactFields(line, parsedWhois, "registrant")
	case "Administrative contact:":
		eew.parseContactFields(line, parsedWhois, "admin")
	case "Technical contact:":
		eew.parseContactFields(line, parsedWhois, "tech")
	case "Registrar:":
		eew.parseRegistrarFields(line, parsedWhois)
	case "Name servers:":
		eew.parseNameserverFields(line, parsedWhois)
	}
}

func (eew *EETLDParser) parseDomainFields(line string, parsedWhois *ParsedWhois) {
	switch {
	case strings.HasPrefix(line, "name:"):
		parsedWhois.DomainName = utils.ExtractField(line, "name:")
	case strings.HasPrefix(line, "status:"):
		status := utils.ExtractField(line, "status:")
		parsedWhois.Statuses = []string{status}
	case strings.HasPrefix(line, "registered:"):
		dateStr := utils.ExtractField(line, "registered:")
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, eeTimeFmt, WhoisTimeFmt)
	case strings.HasPrefix(line, "changed:"):
		dateStr := utils.ExtractField(line, "changed:")
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, eeTimeFmt, WhoisTimeFmt)
	case strings.HasPrefix(line, "expire:"):
		dateStr := utils.ExtractField(line, "expire:")
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate = dateStr // Already in YYYY-MM-DD
	}
}

func (eew *EETLDParser) parseContactFields(line string, parsedWhois *ParsedWhois, contactType string) {
	eew.ensureContact(parsedWhois, contactType)
	var c *Contact
	switch contactType {
	case "registrant":
		c = parsedWhois.Contacts.Registrant
	case "admin":
		c = parsedWhois.Contacts.Admin
	case "tech":
		c = parsedWhois.Contacts.Tech
	default:
		return
	}

	switch {
	case strings.HasPrefix(line, "name:"):
		c.Name = utils.ExtractField(line, "name:")
	case strings.HasPrefix(line, "email:"):
		c.Email = utils.ExtractField(line, "email:")
	case strings.HasPrefix(line, "phone:"):
		c.Phone = utils.ExtractField(line, "phone:")
	case strings.HasPrefix(line, "org id:"):
		c.ID = utils.ExtractField(line, "org id:")
	case strings.HasPrefix(line, "country:"):
		c.Country = utils.ExtractField(line, "country:")
	}
}

func (eew *EETLDParser) parseRegistrarFields(line string, parsedWhois *ParsedWhois) {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	switch {
	case strings.HasPrefix(line, "name:"):
		parsedWhois.Registrar.Name = utils.ExtractField(line, "name:")
	case strings.HasPrefix(line, "url:"):
		parsedWhois.Registrar.URL = utils.ExtractField(line, "url:")
	case strings.HasPrefix(line, "phone:"):
		parsedWhois.Registrar.AbuseContactPhone = utils.ExtractField(line, "phone:")
	}
}

func (eew *EETLDParser) parseNameserverFields(line string, parsedWhois *ParsedWhois) {
	if utils.IsNameserverLine(line, "nserver:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, utils.ExtractField(line, "nserver:"))
	}
}

func (eew *EETLDParser) ensureContact(parsedWhois *ParsedWhois, contactType string) {
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
	case "tech":
		if parsedWhois.Contacts.Tech == nil {
			parsedWhois.Contacts.Tech = &Contact{}
		}
	}
}
