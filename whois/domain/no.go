package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	noTimeFmt = "2006-01-02"
)

type NOParser struct{}

type NOTLDParser struct {
	parser IParser
}

func NewNOTLDParser() *NOTLDParser {
	return &NOTLDParser{
		parser: NewParser(),
	}
}

func (now *NOTLDParser) GetName() string {
	return "no"
}

func (now *NOTLDParser) handleBasicFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Domain Name") {
		parsedWhois.DomainName = extractNOField(line)
		return true
	} else if strings.HasPrefix(line, "Name Server Handle") {
		parsedWhois.NameServers = append(parsedWhois.NameServers, extractNOField(line))
		return true
	}
	return false
}

func (now *NOTLDParser) handleRegistrarFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Registrar Handle") {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = extractNOField(line)
		return true
	}
	return false
}

func (now *NOTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Created:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Created:"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, noTimeFmt, WhoisTimeFmt)
		return true
	} else if strings.HasPrefix(line, "Last updated:") {
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Last updated:"))
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, noTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (now *NOTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "% No match") {
		parsedWhois := &ParsedWhois{}
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if now.handleBasicFields(line, parsedWhois) {
			continue
		}
		if now.handleRegistrarFields(line, parsedWhois) {
			continue
		}
		if now.handleDateFields(line, parsedWhois) {
			continue
		}
	}

	// Set status to "active" for registered domains
	parsedWhois.Statuses = []string{"active"}

	return parsedWhois, nil
}

// Helper to extract the value after the dotted alignment
func extractNOField(line string) string {
	if idx := strings.Index(line, ":"); idx != -1 {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}
