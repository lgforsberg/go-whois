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

	// Parse name servers
	parsedWhois.NameServers = []string{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Nserver:") {
			nsLine := strings.TrimSpace(strings.TrimPrefix(line, "Nserver:"))
			if nsLine != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
			}
		}
	}

	// Parse the Changed date
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Changed:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "Changed:"))
			parsedWhois.UpdatedDateRaw = dateStr
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, deTimeFmt, WhoisTimeFmt)
		}
	}

	// Set status to "connect" for registered domains (clear any existing statuses)
	parsedWhois.Statuses = []string{"connect"}

	return parsedWhois, nil
}
