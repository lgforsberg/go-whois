package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	cnTimeFmt = "2006-01-02 15:04:05"
)

var CNMap = map[string]string{
	"Domain Name":              "domain",
	"Registrant":               "c/registrant/name",
	"Registrant Contact Email": "c/registrant/email",
	"Sponsoring Registrar":     "reg/name",
	"Name Server":              "name_servers",
	"Domain Status":            "statuses",
	"DNSSEC":                   "dnssec",
}

type CNParser struct{}

type CNTLDParser struct {
	parser IParser
}

func NewCNTLDParser() *CNTLDParser {
	return &CNTLDParser{
		parser: NewParser(),
	}
}

func (cnw *CNTLDParser) GetName() string {
	return "cn"
}

func (cnw *CNTLDParser) handleDates(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registration Time:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Registration Time:"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, cnTimeFmt, WhoisTimeFmt)
		return true
	} else if strings.HasPrefix(line, "Expiration Time:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Expiration Time:"))
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, cnTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (cnw *CNTLDParser) handleNameServers(line string, parsedWhois *ParsedWhois) bool {
	if utils.IsNameserverLine(line, "Name Server:") {
		nsLine := strings.TrimSpace(strings.TrimPrefix(line, "Name Server:"))
		if nsLine != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
		}
		return true
	}
	return false
}

func (cnw *CNTLDParser) handleStatuses(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain Status:") {
		statusStr := strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:"))
		if statusStr != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, statusStr)
		}
		return true
	}
	return false
}

func (cnw *CNTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "No matching record.") ||
		strings.Contains(rawtext, "the Domain Name you apply can not be registered online") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois, err := cnw.parser.Do(rawtext, nil, CNMap)
	if err != nil {
		return nil, err
	}

	// Manual parsing for fields not covered by the generic parser
	parsedWhois.NameServers = []string{}
	parsedWhois.Statuses = []string{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if cnw.handleDates(line, parsedWhois) {
			continue
		}
		if cnw.handleNameServers(line, parsedWhois) {
			continue
		}
		if cnw.handleStatuses(line, parsedWhois) {
			continue
		}
	}

	return parsedWhois, nil
}
