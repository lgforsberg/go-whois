package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

var BRMap map[string]string = map[string]string{
	"owner": "c/registrant/name",
}

// BRParser represents a parser for BR domain whois responses.
// Deprecated: Use BRTLDParser instead.
type BRParser struct{}

// BRTLDParser is a specialized parser for .br domain whois responses.
// It handles the specific format used by Registro.br, the Brazilian registry.
type BRTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

// NewBRTLDParser creates a new parser for .br domain whois responses.
// The parser is configured to stop at security notices and handle Brazilian date formats.
func NewBRTLDParser() *BRTLDParser {
	return &BRTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "% Security and mail") },
	}
}

func (brw *BRTLDParser) GetName() string {
	return "br"
}

func (brw *BRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using Brazilian-specific pattern
	if strings.Contains(rawtext, "% No match for") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := brw.parser.Do(rawtext, brw.stopFunc, BRMap)
	if err != nil {
		return nil, err
	}

	var createDone, updateDone, expireDone bool
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		if brw.stopFunc(line) {
			break
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "created":
			if !createDone {
				parsedWhois.CreatedDateRaw = val
				if i := strings.Index(val, "#"); i != -1 {
					val = strings.TrimSpace(val[:i])
				}
				parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(val, WhoisTimeFmt)
				createDone = true
			}
		case "changed":
			if !updateDone {
				parsedWhois.UpdatedDateRaw = val
				parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
				updateDone = true
			}
		case "expires":
			if !expireDone {
				parsedWhois.ExpiredDateRaw = val
				parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
				expireDone = true
			}
		}
	}

	return parsedWhois, nil
}
