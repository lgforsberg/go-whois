package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	awTimeFmt = "2006-01-02"
)

type AWParser struct{}

type AWTLDParser struct {
	parser IParser
}

func NewAWTLDParser() *AWTLDParser {
	return &AWTLDParser{
		parser: NewParser(),
	}
}

func (aww *AWTLDParser) GetName() string {
	return "aw"
}

func (aww *AWTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, " is free") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var inRegistrarSection bool
	var inNameserversSection bool
	var registrarLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Domain name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		} else if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			if status == "active" {
				parsedWhois.Statuses = []string{"active"}
			} else {
				parsedWhois.Statuses = []string{status}
			}
		} else if line == "Registrar:" {
			inRegistrarSection = true
			registrarLines = []string{}
		} else if inRegistrarSection && line != "" && !strings.HasPrefix(line, "DNSSEC:") {
			registrarLines = append(registrarLines, line)
		} else if strings.HasPrefix(line, "DNSSEC:") {
			inRegistrarSection = false
			// Set registrar name from the first line of registrar section
			if len(registrarLines) > 0 {
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				parsedWhois.Registrar.Name = registrarLines[0]
			}
		} else if line == "Domain nameservers:" {
			inNameserversSection = true
		} else if inNameserversSection && line != "" && !strings.HasPrefix(line, "Creation Date:") {
			parsedWhois.NameServers = append(parsedWhois.NameServers, line)
		} else if strings.HasPrefix(line, "Creation Date:") {
			inNameserversSection = false
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, awTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "Updated Date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
			parsedWhois.UpdatedDateRaw = dateStr
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, awTimeFmt, WhoisTimeFmt)
		}
	}

	return parsedWhois, nil
}
