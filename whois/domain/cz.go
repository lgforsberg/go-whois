package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	CZTimeFmt1 = "02.01.2006 15:04:05"
	CZTimeFmt2 = "02.01.2006"
)

var CZMap map[string]string = map[string]string{
	"Registrant": "c/registrant/id",
	"registered": "created_date",
	"registrant": "c/registrant/id",
	"tech-c":     "c/tech/id",
}

type CZTLDParser struct {
	parser IParser
}

func (czw *CZTLDParser) GetName() string {
	return "cz"
}

func NewCZTLDParser() *CZTLDParser {
	return &CZTLDParser{
		parser: NewParser(),
	}
}

func (czw *CZTLDParser) handleDateField(key, val string, parsedWhois *ParsedWhois, flags *dateFlags) {
	switch key {
	case "registered":
		if !flags.createFlg {
			parsedWhois.CreatedDateRaw = val
			flags.createFlg = true
		}
	case "changed":
		if !flags.updateFlg {
			parsedWhois.UpdatedDateRaw = val
			flags.updateFlg = true
		}
	case "expire":
		if !flags.expireFlg {
			parsedWhois.ExpiredDateRaw = val
			flags.expireFlg = true
		}
	}
}

func (czw *CZTLDParser) handleContactField(key, val string, parsedWhois *ParsedWhois, contactFlg *string, contactsMap map[string]map[string]interface{}, regFlg *bool) {
	switch key {
	case "contact":
		czw.handleContactIdentification(val, parsedWhois, contactFlg, contactsMap, regFlg)
	case "name", "org", "address":
		czw.handleContactFieldAssignment(key, val, parsedWhois, contactFlg, contactsMap, regFlg)
	}
}

func (czw *CZTLDParser) handleContactIdentification(val string, parsedWhois *ParsedWhois, contactFlg *string, contactsMap map[string]map[string]interface{}, regFlg *bool) {
	// registrar
	if parsedWhois.Registrar != nil && "REG-"+val == parsedWhois.Registrar.Name {
		*regFlg = true
	}
	// contacts: registrant/tech
	if parsedWhois.Contacts != nil {
		if parsedWhois.Contacts.Registrant != nil && val == parsedWhois.Contacts.Registrant.ID {
			*contactFlg = REGISTRANT
			contactsMap[REGISTRANT] = make(map[string]interface{})
		} else if parsedWhois.Contacts.Tech != nil && val == parsedWhois.Contacts.Tech.ID {
			*contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
		}
	}
}

func (czw *CZTLDParser) handleContactFieldAssignment(key, val string, parsedWhois *ParsedWhois, contactFlg *string, contactsMap map[string]map[string]interface{}, regFlg *bool) {
	if len(*contactFlg) == 0 {
		return
	}
	if *regFlg && key == "name" {
		parsedWhois.Registrar.Name = val
		return
	}
	ckey := key
	if key == "address" {
		ckey = "street"
		if _, ok := contactsMap[*contactFlg][ckey]; !ok {
			contactsMap[*contactFlg][ckey] = []string{}
		}
		contactsMap[*contactFlg][ckey] = append(contactsMap[*contactFlg][ckey].([]string), val)
		return
	}
	if key == "org" {
		ckey = "organization"
	}
	contactsMap[*contactFlg][ckey] = val
}

func (czw *CZTLDParser) cleanNameServers(parsedWhois *ParsedWhois) {
	// Name servers might contains ips
	// E.g., "beta.ns.active24.cz (81.0.238.27, 2001:1528:151::12)"
	for i := 0; i < len(parsedWhois.NameServers); i++ {
		if nss := strings.Split(parsedWhois.NameServers[i], " "); len(nss) > 1 {
			parsedWhois.NameServers[i] = nss[0]
		}
	}
}

func (czw *CZTLDParser) parseDates(parsedWhois *ParsedWhois) {
	// Parsed Time again since it has a weird format
	parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(parsedWhois.CreatedDateRaw, CZTimeFmt1, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(parsedWhois.UpdatedDateRaw, CZTimeFmt1, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(parsedWhois.ExpiredDateRaw, CZTimeFmt2, WhoisTimeFmt)
}

type dateFlags struct {
	createFlg bool
	updateFlg bool
	expireFlg bool
}

func (czw *CZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := czw.parser.Do(rawtext, nil, CZMap)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	flags := &dateFlags{}
	var regFlg bool
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			contactFlg = ""
			continue
		}

		// Handle date fields
		if key == "registered" || key == "changed" || key == "expire" {
			czw.handleDateField(key, val, parsedWhois, flags)
			continue
		}

		// Handle contact fields
		if key == "contact" || key == "name" || key == "org" || key == "address" {
			czw.handleContactField(key, val, parsedWhois, &contactFlg, contactsMap, &regFlg)
		}
	}

	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}

	czw.cleanNameServers(parsedWhois)
	czw.parseDates(parsedWhois)

	return parsedWhois, err
}
