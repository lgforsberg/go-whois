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

type JPParser struct{}

type JPTLDParser struct {
	parser IParser
}

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
		parsedWhois.Statuses = []string{"free"}
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}

	// Parse the response line by line
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse domain name
		if strings.HasPrefix(line, "[Domain Name]") {
			domainStr := strings.TrimSpace(strings.TrimPrefix(line, "[Domain Name]"))
			parsedWhois.DomainName = domainStr
		}

		// Parse registrant name (use Japanese field, fallback to English)
		if strings.HasPrefix(line, "[登録者名]") {
			registrantStr := strings.TrimSpace(strings.TrimPrefix(line, "[登録者名]"))
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = registrantStr
		} else if strings.HasPrefix(line, "[Registrant]") && (parsedWhois.Contacts == nil || parsedWhois.Contacts.Registrant == nil || parsedWhois.Contacts.Registrant.Name == "") {
			registrantStr := strings.TrimSpace(strings.TrimPrefix(line, "[Registrant]"))
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
			parsedWhois.Contacts.Registrant.Name = registrantStr
		}

		// Parse name servers
		if strings.HasPrefix(line, "[Name Server]") {
			nsLine := strings.TrimSpace(strings.TrimPrefix(line, "[Name Server]"))
			if nsLine != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, nsLine)
			}
		}

		// Parse dates
		if strings.HasPrefix(line, "[登録年月日]") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[登録年月日]"))
			parsedWhois.CreatedDateRaw = dateStr
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, jpTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "[有効期限]") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[有効期限]"))
			parsedWhois.ExpiredDateRaw = dateStr
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, jpTimeFmt, WhoisTimeFmt)
		} else if strings.HasPrefix(line, "[最終更新]") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "[最終更新]"))
			parsedWhois.UpdatedDateRaw = dateStr
			// Convert JST to UTC for the parsed date
			if t, err := time.Parse(jpUpdatedFmt, dateStr); err == nil {
				// JST is UTC+9, so subtract 9 hours to get UTC
				utcTime := t.Add(-9 * time.Hour)
				parsedWhois.UpdatedDate = utcTime.Format(WhoisTimeFmt)
			}
		}

		// Parse status
		if strings.HasPrefix(line, "[状態]") {
			statusStr := strings.TrimSpace(strings.TrimPrefix(line, "[状態]"))
			parsedWhois.Statuses = []string{statusStr}
		}
	}

	// Set status to "Active" for registered domains if not already set
	if len(parsedWhois.Statuses) == 0 {
		parsedWhois.Statuses = []string{"Active"}
	}

	return parsedWhois, nil
}
