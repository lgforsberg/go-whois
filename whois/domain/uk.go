package domain

import (
	"sort"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	tFmt = "Monday 2 Jan 2006"
)

var UKMap = map[string]string{
	"URL": "reg/url",
}

// UKParser represents a parser for UK domain whois responses.
// Deprecated: Use UKTLDParser instead.
type UKParser struct{}

// UKTLDParser is a specialized parser for .uk domain whois responses.
// It handles the specific format and fields used by Nominet UK registry.
type UKTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

// NewUKTLDParser creates a new parser for .uk domain whois responses.
// The parser is configured to handle UK-specific date formats and field layouts.
func NewUKTLDParser() *UKTLDParser {
	return &UKTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "--") },
	}
}

func (ukw *UKTLDParser) GetName() string {
	return "uk"
}

func (ukw *UKTLDParser) handleBasicFields(keyword, line string, lines []string, idx int, parsedWhois *ParsedWhois) {
	switch keyword {
	case "Domain name", "Domain":
		parsedWhois.DomainName = strings.TrimSpace(lines[idx+1])
	case "DNSSEC":
		parsedWhois.Dnssec = strings.TrimSpace(lines[idx+1])
	}
}

func (ukw *UKTLDParser) handleRegistrarFields(keyword, line string, lines []string, idx int, parsedWhois *ParsedWhois) {
	if keyword == "Registrar" || keyword == "Domain Owner" {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
	}
}

func (ukw *UKTLDParser) handleNameServers(keyword string, lines []string, idx int, parsedWhois *ParsedWhois) {
	if keyword == "Name servers" || keyword == "Servers" {
		for i := 1; i <= maxNServer; i++ {
			ns := strings.TrimSpace(lines[idx+i])
			if len(ns) == 0 {
				break
			}
			if end := strings.Index(ns, "\t"); end != -1 {
				ns = ns[:end]
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
	}
}

func (ukw *UKTLDParser) handleDateFields(keyword string, lines []string, idx int, parsedWhois *ParsedWhois) {
	switch keyword {
	case "Entry created":
		parsedWhois.CreatedDateRaw = strings.TrimSpace(lines[idx+1])
		adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.CreatedDateRaw)
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
	case "Entry updated":
		parsedWhois.UpdatedDateRaw = strings.TrimSpace(lines[idx+1])
		adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.UpdatedDateRaw)
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
	case "Renewal date":
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(lines[idx+1])
		adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.ExpiredDateRaw)
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
	}
}

func (ukw *UKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using UK-specific patterns
	if strings.Contains(rawtext, "No match for ") &&
		strings.Contains(rawtext, "This domain name has not been registered.") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := ukw.parser.Do(rawtext, ukw.stopFunc, UKMap)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if ukw.stopFunc(line) {
			break
		}
		keyword := strings.TrimRight(line, ":")
		ukw.handleBasicFields(keyword, line, lines, idx, parsedWhois)
		ukw.handleRegistrarFields(keyword, line, lines, idx, parsedWhois)
		ukw.handleNameServers(keyword, lines, idx, parsedWhois)
		ukw.handleDateFields(keyword, lines, idx, parsedWhois)
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}

func removeStRdNdThAndTrimMonInTime(t string) string {
	// Tuesday 1st Feb 2022 -> Tuesday 1 Feb 2022
	// Wednesday 13th October 2021 -> Wednesday 13 Oct 2021
	ts := strings.Split(t, " ")
	if len(ts) < 3 {
		return t
	}
	ts[1] = dayReplacer.Replace(ts[1])
	if len(ts[2]) > 3 {
		ts[2] = ts[2][:3]
	}
	return strings.Join(ts, " ")
}
