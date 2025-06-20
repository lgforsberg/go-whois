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

		// Extract domain name
		if strings.HasPrefix(line, "domain:") {
			parsed.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
			continue
		}

		// Extract registrar
		if strings.HasPrefix(line, "registrar:") {
			parsed.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "registrar:"))
			continue
		}

		// Extract registrar URL
		if strings.HasPrefix(line, "registrar-url:") {
			parsed.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "registrar-url:"))
			continue
		}

		// Extract nameservers
		if strings.HasPrefix(line, "nameserver:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver:"))
			if ns != "" {
				parsed.NameServers = append(parsed.NameServers, ns)
			}
			continue
		}

		// Extract registrant
		if strings.HasPrefix(line, "registrant:") {
			registrant := strings.TrimSpace(strings.TrimPrefix(line, "registrant:"))
			if registrant != "" && registrant != "NOT DISCLOSED" {
				parsed.Contacts.Registrant = &Contact{
					ID: registrant,
				}
			}
			continue
		}

		// Extract status
		if strings.HasPrefix(line, "status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
			if status != "" {
				// Split multiple statuses by comma
				statuses := strings.Split(status, ",")
				for _, s := range statuses {
					s = strings.TrimSpace(s)
					if s != "" {
						parsed.Statuses = append(parsed.Statuses, s)
					}
				}
			}
			continue
		}

		// Extract created date
		if strings.HasPrefix(line, "created:") {
			created := strings.TrimSpace(strings.TrimPrefix(line, "created:"))
			if created != "" {
				parsed.CreatedDateRaw = created
			}
			continue
		}

		// Extract expire date
		if strings.HasPrefix(line, "expire:") {
			expire := strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
			if expire != "" {
				parsed.ExpiredDateRaw = expire
			}
			continue
		}
	}

	// Add date format conversion
	parsed.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsed.CreatedDateRaw, WhoisTimeFmt)
	parsed.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsed.ExpiredDateRaw, WhoisTimeFmt)

	return parsed, nil
}
