package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

type MXTLDParser struct {
	parser IParser
}

func NewMXTLDParser() *MXTLDParser {
	return &MXTLDParser{
		parser: NewParser(),
	}
}

func (mxw *MXTLDParser) GetName() string {
	return "mx"
}

func (mxw *MXTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "No_Se_Encontro_El_Objeto/Object_Not_Found") {
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	var inNameServers bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Created On:") {
			parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created On:"))
		} else if strings.HasPrefix(line, "Expiration Date:") {
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expiration Date:"))
		} else if strings.HasPrefix(line, "Last Updated On:") {
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Last Updated On:"))
		} else if strings.HasPrefix(line, "Registrar:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "URL:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.URL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
		} else if strings.HasPrefix(line, "Name Servers:") {
			inNameServers = true
			continue
		} else if inNameServers {
			if strings.HasPrefix(line, "DNS:") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "DNS:"))
				if ns != "" {
					parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
				}
			} else if line == "DNSSEC DS Records:" {
				inNameServers = false
			}
		}
	}

	// Add status assignment for registered domains
	if parsedWhois.DomainName != "" {
		parsedWhois.Statuses = []string{"Active"}
	}

	// Add date format conversion
	parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)

	return parsedWhois, nil
}
