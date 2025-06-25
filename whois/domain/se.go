package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	seTimeFmt = "2006-01-02"
)

var SEMap = map[string]string{
	"domain":    "domain",
	"state":     "statuses",
	"created":   "created_date",
	"modified":  "updated_date",
	"expires":   "expired_date",
	"nserver":   "name_servers",
	"dnssec":    "dnssec",
	"registrar": "reg/name",
}

type SEParser struct{}

// SETLDParser is a specialized parser for .se domain whois responses.
// It handles the specific format used by IIS, the Swedish Internet Infrastructure Foundation.
type SETLDParser struct {
	parser IParser
}

// NewSETLDParser creates a new parser for .se domain whois responses.
// The parser is configured to handle Swedish registry field layouts and date formats.
func NewSETLDParser() *SETLDParser {
	return &SETLDParser{
		parser: NewParser(),
	}
}

func (sew *SETLDParser) GetName() string {
	return "se"
}

func (sew *SETLDParser) handleDates(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "created:") {
		dateStr := utils.ExtractField(line, "created:")
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, seTimeFmt, WhoisTimeFmt)
	} else if strings.HasPrefix(line, "modified:") {
		dateStr := utils.ExtractField(line, "modified:")
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, seTimeFmt, WhoisTimeFmt)
	} else if strings.HasPrefix(line, "expires:") {
		dateStr := utils.ExtractField(line, "expires:")
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, seTimeFmt, WhoisTimeFmt)
	}
}

func (sew *SETLDParser) handleNameServers(line string, parsedWhois *ParsedWhois) {
	if utils.IsNameserverLine(line, "nserver:") {
		nsLine := utils.ExtractField(line, "nserver:")
		if nsLine != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
		}
	}
}

func (sew *SETLDParser) handleStatuses(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "status:") {
		statusStr := utils.ExtractField(line, "status:")
		if statusStr != "" {
			parsedWhois.Statuses = append(parsedWhois.Statuses, statusStr)
		}
	}
}

func (sew *SETLDParser) handleState(line string, parsedWhois *ParsedWhois) {
	if strings.HasPrefix(line, "state:") {
		stateStr := utils.ExtractField(line, "state:")
		if stateStr != "" {
			parsedWhois.Statuses = []string{stateStr}
		}
	}
}

func (sew *SETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "not found.") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := sew.parser.Do(rawtext, nil, SEMap)
	if err != nil {
		return nil, err
	}

	// Parse the response line by line
	lines := strings.Split(rawtext, "\n")
	parsedWhois.NameServers = []string{}
	parsedWhois.Statuses = []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		sew.handleDates(line, parsedWhois)
		sew.handleNameServers(line, parsedWhois)
		sew.handleStatuses(line, parsedWhois)
	}

	// Set state as status if no other statuses found
	if len(parsedWhois.Statuses) == 0 {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			sew.handleState(line, parsedWhois)
			if len(parsedWhois.Statuses) > 0 {
				break
			}
		}
	}

	return parsedWhois, nil
}
