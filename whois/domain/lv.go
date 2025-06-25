package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type LVTLDParser struct {
	parser IParser
}

func NewLVTLDParser() *LVTLDParser {
	return &LVTLDParser{
		parser: NewParser(),
	}
}

func (lvw *LVTLDParser) GetName() string {
	return "lv"
}

func (lvw *LVTLDParser) handleDomainSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Domain:") {
		parsedWhois.DomainName = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Status:") {
		status := utils.ExtractValue(line)
		if status == "free" {
			SetDomainAvailabilityStatus(parsedWhois, true)
			return
		}
		parsedWhois.Statuses = []string{status}
	}
}

func (lvw *LVTLDParser) handleHolderSection(line string, parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}

	if strings.HasPrefix(line, "Name:") {
		parsedWhois.Contacts.Registrant.Name = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Country:") {
		parsedWhois.Contacts.Registrant.Country = utils.ExtractValue(line)
	} else if strings.HasPrefix(line, "Address:") {
		parsedWhois.Contacts.Registrant.Street = []string{utils.ExtractValue(line)}
	}
}

func (lvw *LVTLDParser) handleRegistrarSection(line string, parsedWhois *ParsedWhois) {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	if strings.HasPrefix(line, "Name:") {
		parsedWhois.Registrar.Name = utils.ExtractValue(line)
	}
}

func (lvw *LVTLDParser) handleNserversSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Nserver:") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, utils.ExtractValue(line))
	}
}

func (lvw *LVTLDParser) handleWhoisSection(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "Updated:") {
		parsedWhois.UpdatedDateRaw = utils.ExtractValue(line)
	}
}

func (lvw *LVTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		switch currentSection {
		case "Domain":
			lvw.handleDomainSection(line, parsedWhois)
			if len(parsedWhois.Statuses) >= 2 && parsedWhois.Statuses[0] == "free" && parsedWhois.Statuses[1] == "not_found" {
				return parsedWhois, nil
			}
		case "Holder":
			lvw.handleHolderSection(line, parsedWhois)
		case "Registrar":
			lvw.handleRegistrarSection(line, parsedWhois)
		case "Nservers":
			lvw.handleNserversSection(line, parsedWhois)
		case "Whois":
			lvw.handleWhoisSection(line, parsedWhois)
		}
	}

	return parsedWhois, nil
}
