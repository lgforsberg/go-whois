package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	deTimeFmt = "2006-01-02T15:04:05-07:00"
)

var DEMap = map[string]string{
	"Domain": "domain",
	"Status": "statuses",
}

// DEParser represents a parser for DE domain whois responses.
// Deprecated: Use DETLDParser instead.
type DEParser struct{}

// DETLDParser is a specialized parser for .de domain whois responses.
// It handles the specific format used by DENIC, the German registry.
type DETLDParser struct {
	parser IParser
}

// NewDETLDParser creates a new parser for .de domain whois responses.
// The parser is configured to handle German registry date formats and field layouts.
func NewDETLDParser() *DETLDParser {
	return &DETLDParser{
		parser: NewParser(),
	}
}

func (dew *DETLDParser) GetName() string {
	return "de"
}

func (dew *DETLDParser) handleNameServers(line string, parsedWhois *ParsedWhois) bool {
	if utils.IsNameserverLine(line, "Nserver:") {
		nsLine := utils.ExtractField(line, "Nserver:")
		if nsLine != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
		}
		return true
	}
	return false
}

func (dew *DETLDParser) handleChangedDate(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "Changed:") {
		dateStr := utils.ExtractField(line, "Changed:")
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, deTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (dew *DETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := dew.parser.Do(rawtext, nil, DEMap)
	if err != nil {
		return nil, err
	}

	// Check if domain is available (Status: free)
	if strings.Contains(rawtext, "Status: free") {
		parsedWhois := &ParsedWhois{}

		// Extract domain name from the rawtext before setting status
		lines := strings.Split(rawtext, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Domain:") {
				parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain:"))
				break
			}
		}

		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	// Parse name servers and Changed date from raw text
	parsedWhois.NameServers = []string{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if dew.handleNameServers(line, parsedWhois) {
			continue
		}
		if dew.handleChangedDate(line, parsedWhois) {
			continue
		}
	}

	// Set status to "connect" for registered domains (clear any existing statuses)
	parsedWhois.Statuses = []string{"connect"}

	return parsedWhois, nil
}
