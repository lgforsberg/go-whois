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

		if aww.parseTopLevelFields(line, parsedWhois) {
			continue
		}
		if sec := aww.handleSectionChange(line, &inRegistrarSection, &inNameserversSection); sec != "" {
			if sec == "registrar" {
				registrarLines = []string{}
			}
			continue
		}
		if aww.parseRegistrarSection(line, inRegistrarSection, &registrarLines, parsedWhois) {
			continue
		}
		if aww.parseNameserversSection(line, &inNameserversSection, parsedWhois) {
			continue
		}
		if aww.parseDates(line, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}

func (aww *AWTLDParser) parseTopLevelFields(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Domain name:"):
		parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain name:"))
		return true
	case strings.HasPrefix(line, "Status:"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		if status == "active" {
			parsedWhois.Statuses = []string{"active"}
		} else {
			parsedWhois.Statuses = []string{status}
		}
		return true
	}
	return false
}

func (aww *AWTLDParser) handleSectionChange(line string, inRegistrarSection, inNameserversSection *bool) string {
	switch line {
	case "Registrar:":
		*inRegistrarSection = true
		*inNameserversSection = false
		return "registrar"
	case "Domain nameservers:":
		*inRegistrarSection = false
		*inNameserversSection = true
		return "nameservers"
	}
	return ""
}

func (aww *AWTLDParser) parseRegistrarSection(line string, inRegistrarSection bool, registrarLines *[]string, parsedWhois *ParsedWhois) bool {
	if !inRegistrarSection {
		return false
	}
	if line == "" || strings.HasPrefix(line, "DNSSEC:") {
		// End of registrar section, set registrar name
		if len(*registrarLines) > 0 {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = (*registrarLines)[0]
		}
		return true
	}
	*registrarLines = append(*registrarLines, line)
	return true
}

func (aww *AWTLDParser) parseNameserversSection(line string, inNameserversSection *bool, parsedWhois *ParsedWhois) bool {
	if !*inNameserversSection {
		return false
	}
	if strings.HasPrefix(line, "Creation Date:") {
		// End of nameservers section, parse the date
		*inNameserversSection = false
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, awTimeFmt, WhoisTimeFmt)
		return true
	}
	if line != "" {
		parsedWhois.NameServers = append(parsedWhois.NameServers, line)
		return true
	}
	return false
}

func (aww *AWTLDParser) parseDates(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Updated Date:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, awTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}
