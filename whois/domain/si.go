package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

// SITLDParser implements ITLDParser for .si domains
type SITLDParser struct {
	parser IParser
}

// NewSITLDParser creates a new .si TLD parser
func NewSITLDParser() *SITLDParser {
	return &SITLDParser{
		parser: NewParser(),
	}
}

// GetName returns the name of the parser
func (p *SITLDParser) GetName() string {
	return "si"
}

func (p *SITLDParser) handleBasicFields(line string, parsed *ParsedWhois) bool {
	if strings.HasPrefix(line, "domain:") {
		parsed.DomainName = utils.ExtractField(line, "domain:")
		return true
	} else if strings.HasPrefix(line, "status:") {
		status := utils.ExtractField(line, "status:")
		if status != "" {
			statuses := strings.Split(status, ",")
			for _, s := range statuses {
				s = strings.TrimSpace(s)
				if s != "" {
					parsed.Statuses = append(parsed.Statuses, s)
				}
			}
		}
		return true
	}
	return false
}

func (p *SITLDParser) handleRegistrarFields(line string, parsed *ParsedWhois) bool {
	if utils.IsRegistrarLine(line, "registrar:") {
		parsed.Registrar.Name = utils.ExtractField(line, "registrar:")
		return true
	} else if strings.HasPrefix(line, "registrar-url:") {
		parsed.Registrar.URL = utils.ExtractField(line, "registrar-url:")
		return true
	}
	return false
}

func (p *SITLDParser) handleNameServerFields(line string, parsed *ParsedWhois) bool {
	if utils.IsNameserverLine(line, "nameserver:") {
		ns := utils.ExtractField(line, "nameserver:")
		if ns != "" {
			parsed.NameServers = append(parsed.NameServers, ns)
		}
		return true
	}
	return false
}

func (p *SITLDParser) handleContactFields(line string, parsed *ParsedWhois) bool {
	if strings.HasPrefix(line, "registrant:") {
		registrant := utils.ExtractField(line, "registrant:")
		if registrant != "" && registrant != "NOT DISCLOSED" {
			parsed.Contacts.Registrant = &Contact{
				ID: registrant,
			}
		}
		return true
	}
	return false
}

func (p *SITLDParser) handleDateFields(line string, parsed *ParsedWhois) bool {
	if strings.HasPrefix(line, "created:") {
		created := utils.ExtractField(line, "created:")
		if created != "" {
			parsed.CreatedDateRaw = created
		}
		return true
	} else if strings.HasPrefix(line, "expire:") {
		expire := utils.ExtractField(line, "expire:")
		if expire != "" {
			parsed.ExpiredDateRaw = expire
		}
		return true
	}
	return false
}

// GetParsedWhois parses the whois response for .si domains
func (p *SITLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsed := &ParsedWhois{
		DomainName:  "",
		Registrar:   &Registrar{},
		CreatedDate: "",
		ExpiredDate: "",
		UpdatedDate: "",
		Statuses:    []string{},
		NameServers: []string{},
		Contacts:    &Contacts{},
	}

	lines := strings.Split(rawtext, "\n")

	// Check if domain is not found
	if strings.Contains(rawtext, "No entries found for the selected source(s).") {
		return parsed, nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		if p.handleBasicFields(line, parsed) {
			continue
		}
		if p.handleRegistrarFields(line, parsed) {
			continue
		}
		if p.handleNameServerFields(line, parsed) {
			continue
		}
		if p.handleContactFields(line, parsed) {
			continue
		}
		if p.handleDateFields(line, parsed) {
			continue
		}
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
