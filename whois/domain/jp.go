package domain

import (
	"strings"
	"time"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	jpTimeFmt    = "2006/01/02"
	jpUpdatedFmt = "2006/01/02 15:04:05 (JST)"
)

var JPMap = map[string]string{
	"[Domain Name]": "domain",
	"[登録者名]":        "c/registrant/name",
	"[Registrant]":  "c/registrant/name",
	"[状態]":          "statuses",
	"[Name Server]": "name_servers",
}

// JPParser represents a parser for JP domain whois responses.
// Deprecated: Use JPTLDParser instead.
type JPParser struct{}

// JPTLDParser is a specialized parser for .jp domain whois responses.
// It handles both Japanese and English field names and JST timezone conversion.
type JPTLDParser struct {
	parser IParser
}

// NewJPTLDParser creates a new parser for .jp domain whois responses.
// The parser handles both Japanese (登録者名, 状態) and English field names,
// and automatically converts JST timestamps to UTC.
func NewJPTLDParser() *JPTLDParser {
	return &JPTLDParser{
		parser: NewParser(),
	}
}

func (jpw *JPTLDParser) GetName() string {
	return "jp"
}

func (jpw *JPTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "No match!!") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}

	// Parse the response line by line
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if jpw.parseDomainName(line, parsedWhois) {
			continue
		}
		if jpw.parseRegistrant(line, parsedWhois) {
			continue
		}
		if jpw.parseNameServers(line, parsedWhois) {
			continue
		}
		if jpw.parseDates(line, parsedWhois) {
			continue
		}
		if jpw.parseStatus(line, parsedWhois) {
			continue
		}
	}

	// Set status to "Active" for registered domains if not already set
	if len(parsedWhois.Statuses) == 0 {
		parsedWhois.Statuses = []string{"Active"}
	}

	return parsedWhois, nil
}

func (jpw *JPTLDParser) parseDomainName(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "[Domain Name]") {
		domainStr := strings.TrimSpace(strings.TrimPrefix(line, "[Domain Name]"))
		parsedWhois.DomainName = domainStr
		return true
	}
	return false
}

func (jpw *JPTLDParser) parseRegistrant(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "[登録者名]"):
		registrantStr := strings.TrimSpace(strings.TrimPrefix(line, "[登録者名]"))
		jpw.ensureRegistrant(parsedWhois)
		parsedWhois.Contacts.Registrant.Name = registrantStr
		return true
	case strings.HasPrefix(line, "[Registrant]") && (parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil || parsedWhois.Contacts.Registrant.Name == ""):
		registrantStr := strings.TrimSpace(strings.TrimPrefix(line, "[Registrant]"))
		jpw.ensureRegistrant(parsedWhois)
		parsedWhois.Contacts.Registrant.Name = registrantStr
		return true
	}
	return false
}

func (jpw *JPTLDParser) ensureRegistrant(parsedWhois *ParsedWhois) {
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}
	if parsedWhois.Contacts.Registrant == nil {
		parsedWhois.Contacts.Registrant = &Contact{}
	}
}

func (jpw *JPTLDParser) parseNameServers(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "[Name Server]") {
		nsLine := strings.TrimSpace(strings.TrimPrefix(line, "[Name Server]"))
		if nsLine != "" {
			parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
		}
		return true
	}
	return false
}

func (jpw *JPTLDParser) parseDates(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "[登録年月日]"):
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[登録年月日]"))
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, jpTimeFmt, WhoisTimeFmt)
		return true
	case strings.HasPrefix(line, "[有効期限]"):
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[有効期限]"))
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, jpTimeFmt, WhoisTimeFmt)
		return true
	case strings.HasPrefix(line, "[最終更新]"):
		dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[最終更新]"))
		parsedWhois.UpdatedDateRaw = dateStr
		// Convert JST to UTC for the parsed date
		if t, err := time.Parse(jpUpdatedFmt, dateStr); err == nil {
			// JST is UTC+9, so subtract 9 hours to get UTC
			utcTime := t.Add(-9 * time.Hour)
			parsedWhois.UpdatedDate = utcTime.Format(WhoisTimeFmt)
		}
		return true
	}
	return false
}

func (jpw *JPTLDParser) parseStatus(line string, parsedWhois *ParsedWhois) bool {
	if strings.HasPrefix(line, "[状態]") {
		statusStr := strings.TrimSpace(strings.TrimPrefix(line, "[状態]"))
		parsedWhois.Statuses = []string{statusStr}
		return true
	}
	return false
}
