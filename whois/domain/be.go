package domain

import (
	"sort"
	"strings"
)

type BEParser struct{}

type BETLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewBETLDParser() *BETLDParser {
	return &BETLDParser{
		parser: NewParser(),
	}
}

func (bew *BETLDParser) GetName() string {
	return "be"
}

func (bew *BETLDParser) handleBasicFields(key, val string, parsedWhois *ParsedWhois) bool {
	if key == "Status" {
		parsedWhois.Statuses = []string{val}
		return true
	}
	return false
}

func (bew *BETLDParser) handleRegistrarSection(key string, regFlg *bool, parsedWhois *ParsedWhois) bool {
	if key == "Registrar" {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		*regFlg = true
		return true
	}
	return false
}

func (bew *BETLDParser) handleNameServers(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Nameservers" {
		parsedWhois.NameServers = []string{}
		for i := 1; i <= maxNServer; i++ {
			ns := strings.TrimSpace(lines[idx+i])
			if len(ns) == 0 {
				break
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
		return true
	}
	return false
}

func (bew *BETLDParser) handleFlags(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Flags" {
		for i := 1; i <= maxNServer; i++ {
			ns := strings.TrimSpace(lines[idx+i])
			if len(ns) == 0 {
				break
			}
			parsedWhois.Statuses = append(parsedWhois.Statuses, ns)
		}
		return true
	}
	return false
}

func (bew *BETLDParser) handleRegistrarDetails(key, val string, regFlg bool, parsedWhois *ParsedWhois) bool {
	if !regFlg {
		return false
	}

	switch key {
	case "Name":
		parsedWhois.Registrar.Name = val
		return true
	case "Website":
		parsedWhois.Registrar.URL = val
		return true
	case "Phone":
		parsedWhois.Registrar.AbuseContactPhone = val
		return true
	}
	return false
}

func (bew *BETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := bew.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var regFlg bool
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, _ := getKeyValFromLine(line)

		// Handle basic fields
		if bew.handleBasicFields(key, val, parsedWhois) {
			continue
		}

		// Handle registrar section
		if bew.handleRegistrarSection(key, &regFlg, parsedWhois) {
			continue
		}

		// Handle name servers
		if bew.handleNameServers(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle flags
		if bew.handleFlags(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle registrar details
		bew.handleRegistrarDetails(key, val, regFlg, parsedWhois)
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
