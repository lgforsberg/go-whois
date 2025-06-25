package domain

import (
	"sort"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	plTimeFmt = "2006.01.02 15:04:05"
)

var PLMap = map[string]string{
	"DOMAIN NAME":            "domain",
	"registrar":              "reg/name",
	"registration date":      "created_date",
	"last modified":          "updated_date",
	"renewal date":           "expired_date",
	"option expiration date": "expired_date",
	"nameservers":            "name_servers",
	"dnssec":                 "dnssec",
}

type PLParser struct{}

// PLTLDParser is a specialized parser for .pl domain whois responses.
// It handles the specific format used by NASK, the Polish registry.
type PLTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

// NewPLTLDParser creates a new parser for .pl domain whois responses.
// The parser is configured to handle Polish registry field layouts and stop at WHOIS data protection information.
func NewPLTLDParser() *PLTLDParser {
	return &PLTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "WHOIS displays data") },
	}
}

func (plw *PLTLDParser) GetName() string {
	return "pl"
}

func (plw *PLTLDParser) handleDateFields(key, val string, parsedWhois *ParsedWhois) bool {
	switch key {
	case "created":
		parsedWhois.CreatedDateRaw = val
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		return true
	case "last modified":
		parsedWhois.UpdatedDateRaw = val
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		return true
	case "renewal date":
		parsedWhois.ExpiredDateRaw = val
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		return true
	}
	return false
}

func (plw *PLTLDParser) handleRegistrarFields(key, val string, lines []string, idx int, regFlg *bool, parsedWhois *ParsedWhois) bool {
	switch key {
	case "REGISTRAR":
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
		*regFlg = true
		return true
	case "Telephone":
		if *regFlg {
			parsedWhois.Registrar.AbuseContactPhone = val
		}
		return true
	case "Email":
		if *regFlg {
			parsedWhois.Registrar.AbuseContactEmail = val
		}
		return true
	}
	return false
}

func (plw *PLTLDParser) handleNameServers(key string, err error, nsFlg *bool, parsedWhois *ParsedWhois) bool {
	if key == "nameservers" {
		*nsFlg = true
		return true
	}

	if *nsFlg && len(key) > 0 && err != nil && len(parsedWhois.NameServers) > 0 {
		ns := strings.Split(key, " ")[0]
		parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		return true
	} else {
		*nsFlg = false
	}
	return false
}

func (plw *PLTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using Polish-specific pattern
	if strings.Contains(rawtext, "No information available about domain name") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := plw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var nsFlg, regFlg bool
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		key, val, err := getKeyValFromLine(line)

		// Handle date fields
		if plw.handleDateFields(key, val, parsedWhois) {
			continue
		}

		// Handle registrar fields
		if plw.handleRegistrarFields(key, val, lines, idx, &regFlg, parsedWhois) {
			continue
		}

		// Handle name servers
		plw.handleNameServers(key, err, &nsFlg, parsedWhois)
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
