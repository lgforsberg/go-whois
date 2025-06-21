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

type DEParser struct{}

type DETLDParser struct {
	parser IParser
}

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
		parsedWhois.Statuses = []string{"free"}
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
