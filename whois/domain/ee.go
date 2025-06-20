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
		if line == "" {
			continue
		}
		if line == "Domain:" || line == "Registrant:" || line == "Administrative contact:" || line == "Technical contact:" || line == "Registrar:" || line == "Name servers:" {
			section = line
			continue
		}

		switch section {
		case "Domain:":
			if strings.HasPrefix(line, "name:") {
				parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			} else if strings.HasPrefix(line, "status:") {
				status := strings.TrimSpace(strings.TrimPrefix(line, "status:"))
				parsedWhois.Statuses = []string{status}
			} else if strings.HasPrefix(line, "registered:") {
				dateStr := strings.TrimSpace(strings.TrimPrefix(line, "registered:"))
				parsedWhois.CreatedDateRaw = dateStr
				parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, eeTimeFmt, WhoisTimeFmt)
			} else if strings.HasPrefix(line, "changed:") {
				dateStr := strings.TrimSpace(strings.TrimPrefix(line, "changed:"))
				parsedWhois.UpdatedDateRaw = dateStr
				parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, eeTimeFmt, WhoisTimeFmt)
			} else if strings.HasPrefix(line, "expire:") {
				dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expire:"))
				parsedWhois.ExpiredDateRaw = dateStr
				parsedWhois.ExpiredDate = dateStr // Already in YYYY-MM-DD
			}
		case "Registrant:":
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			if strings.HasPrefix(line, "name:") {
				parsedWhois.Contacts.Registrant.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			} else if strings.HasPrefix(line, "org id:") {
				parsedWhois.Contacts.Registrant.ID = strings.TrimSpace(strings.TrimPrefix(line, "org id:"))
			} else if strings.HasPrefix(line, "country:") {
				parsedWhois.Contacts.Registrant.Country = strings.TrimSpace(strings.TrimPrefix(line, "country:"))
			} else if strings.HasPrefix(line, "email:") {
				parsedWhois.Contacts.Registrant.Email = strings.TrimSpace(strings.TrimPrefix(line, "email:"))
			} else if strings.HasPrefix(line, "phone:") {
				parsedWhois.Contacts.Registrant.Phone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
			}
		case "Administrative contact:":
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Admin == nil {
				parsedWhois.Contacts.Admin = &Contact{}
			}
			if strings.HasPrefix(line, "name:") {
				parsedWhois.Contacts.Admin.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			} else if strings.HasPrefix(line, "email:") {
				parsedWhois.Contacts.Admin.Email = strings.TrimSpace(strings.TrimPrefix(line, "email:"))
			}
		case "Technical contact:":
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Tech == nil {
				parsedWhois.Contacts.Tech = &Contact{}
			}
			if strings.HasPrefix(line, "name:") {
				parsedWhois.Contacts.Tech.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			} else if strings.HasPrefix(line, "email:") {
				parsedWhois.Contacts.Tech.Email = strings.TrimSpace(strings.TrimPrefix(line, "email:"))
			}
		case "Registrar:":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			if strings.HasPrefix(line, "name:") {
				parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
			} else if strings.HasPrefix(line, "url:") {
				parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "url:"))
			} else if strings.HasPrefix(line, "phone:") {
				parsedWhois.Registrar.AbuseContactPhone = strings.TrimSpace(strings.TrimPrefix(line, "phone:"))
			}
		case "Name servers:":
			if strings.HasPrefix(line, "nserver:") {
				parsedWhois.NameServers = append(parsedWhois.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "nserver:")))
			}
		}
	}

	return parsedWhois, nil
}
