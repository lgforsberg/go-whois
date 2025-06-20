package domain

import (
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	twTimeFmt = "2006-01-02 15:04:05 (UTC+8)"

	createdDateKW = "Record created on "
	expiresDateKW = "Record expires on "
)

type TWParser struct{}

var (
	twloc, _ = time.LoadLocation("Asia/Taipei")
)

// the line after contact keyword: <name>  <email>
// note: name and email is separated by **two spaces**
func isNameAndEmailContactLine(line string) (name, email string, isLine bool) {
	nameAndMail := strings.Split(line, "  ")
	if len(nameAndMail) != 2 {
		return "", "", false
	}
	if _, err := mail.ParseAddress(nameAndMail[1]); err == nil {
		return nameAndMail[0], nameAndMail[1], true
	}
	return "", "", false
}

type TWTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewTWTLDParser() *TWTLDParser {
	return &TWTLDParser{
		parser: NewParser(),
	}
}

func (tww *TWTLDParser) GetName() string {
	return "tw"
}

func (tww *TWTLDParser) handleDateFields(line string, parsedWhois *ParsedWhois) bool {
	if kwIdx := strings.Index(line, expiresDateKW); kwIdx != -1 {
		parsedWhois.ExpiredDateRaw = line[kwIdx+len(expiresDateKW):]
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmtInLocation(
			parsedWhois.ExpiredDateRaw, twTimeFmt, WhoisTimeFmt, twloc)
		return true
	}
	if kwIdx := strings.Index(line, createdDateKW); kwIdx != -1 {
		parsedWhois.CreatedDateRaw = line[kwIdx+len(createdDateKW):]
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmtInLocation(
			parsedWhois.CreatedDateRaw, twTimeFmt, WhoisTimeFmt, twloc)
		return true
	}
	return false
}

func (tww *TWTLDParser) handleNameServers(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Domain servers in listed order" {
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

func (tww *TWTLDParser) handleContactSection(key string, contactFlg *string, contactsMap map[string]map[string]interface{}) bool {
	switch key {
	case "Registrant":
		*contactFlg = REGISTRANT
		contactsMap[REGISTRANT] = make(map[string]interface{})
		return true
	case "Administrative Contact":
		*contactFlg = ADMIN
		contactsMap[ADMIN] = make(map[string]interface{})
		return true
	case "Technical Contact":
		*contactFlg = TECH
		contactsMap[TECH] = make(map[string]interface{})
		return true
	}
	return false
}

func (tww *TWTLDParser) handleRegistrarFields(key, val string, parsedWhois *ParsedWhois) bool {
	switch key {
	case "Registration Service Provider":
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = val
		return true
	case "Registration Service URL":
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.URL = val
		return true
	}
	return false
}

func (tww *TWTLDParser) handleContactDetails(key, line string, contactFlg string, contactsMap map[string]map[string]interface{}) {
	if len(key) == 0 {
		return
	}
	if len(contactFlg) > 0 {
		if len(key) == 2 {
			contactsMap[contactFlg]["country"] = key
		}
		if name, mail, isContactInfoLine := isNameAndEmailContactLine(line); isContactInfoLine {
			contactsMap[contactFlg]["name"] = name
			contactsMap[contactFlg]["email"] = mail
		}
	}
}

func (tww *TWTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := tww.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line := strings.TrimSpace(line)

		// Handle date fields
		if tww.handleDateFields(line, parsedWhois) {
			continue
		}

		key, val, _ := getKeyValFromLine(line)

		// Handle name servers
		if tww.handleNameServers(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle contact sections
		if tww.handleContactSection(key, &contactFlg, contactsMap) {
			continue
		}

		// Handle registrar fields
		if tww.handleRegistrarFields(key, val, parsedWhois) {
			continue
		}

		// Handle contact details
		tww.handleContactDetails(key, line, contactFlg, contactsMap)
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
