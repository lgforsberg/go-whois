package domain

import (
	"net/mail"
	"sort"
	"strings"
)

type AMParser struct{}

type AMTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewAMTLDParser() *AMTLDParser {
	return &AMTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "--") },
	}
}

func (amw *AMTLDParser) GetName() string {
	return "am"
}

func (amw *AMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := amw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	amw.parseDNSServers(lines, parsedWhois)
	amw.parseContacts(lines, contactsMap)

	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}

func (amw *AMTLDParser) parseDNSServers(lines []string, parsedWhois *ParsedWhois) {
	for idx, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		line = strings.TrimSpace(line)
		if strings.TrimRight(line, ":") == "DNS servers" {
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		}
	}
}

func (amw *AMTLDParser) parseContacts(lines []string, contactsMap map[string]map[string]interface{}) {
	var contactFlg string
	for idx, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		line = strings.TrimSpace(line)
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "Registrant":
			contactFlg = REGISTRANT
			contactsMap[REGISTRANT] = make(map[string]interface{})
			contactsMap[REGISTRANT]["name"] = strings.TrimSpace(lines[idx+1])
		case "Administrative contact":
			contactFlg = ADMIN
			contactsMap[ADMIN] = make(map[string]interface{})
			contactsMap[ADMIN]["name"] = strings.TrimSpace(lines[idx+2])
		case "Technical contact":
			contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
			contactsMap[TECH]["name"] = strings.TrimSpace(lines[idx+2])
		default:
			if len(keyword) == 0 {
				continue
			}
			if len(contactFlg) > 0 {
				if len(keyword) == 2 {
					contactsMap[contactFlg]["country"] = keyword
				}
				if _, err := mail.ParseAddress(keyword); err == nil {
					contactsMap[contactFlg]["email"] = keyword
				}
			}
		}
	}
}
