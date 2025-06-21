package domain

import (
	"sort"
	"strings"
)

var tkMap = map[string]string{
	"Domain registered":     "created_date",
	"Record will expire on": "expired_date",
}

var tkContactKeyMap = map[string]string{
	"zipcode": "postal",
	"e-mail":  "email",
	"address": "street",
}

type TKTLDParser struct {
	parser IParser
}

func NewTKTLDParser() *TKTLDParser {
	return &TKTLDParser{
		parser: NewParser(),
	}
}

func (tkw *TKTLDParser) GetName() string {
	return "tk"
}

func (tkw *TKTLDParser) handleBasicFields(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Domain name" {
		parsedWhois.DomainName = strings.TrimRight(strings.TrimSpace(lines[idx+1]), " is Active")
		return true
	}
	return false
}

func (tkw *TKTLDParser) handleContactSection(key string, contactFlg *string, contactsMap map[string]map[string]interface{}) bool {
	switch key {
	case "Owner contact":
		*contactFlg = REGISTRANT
		contactsMap[REGISTRANT] = make(map[string]interface{})
		return true
	case "Admin contact":
		*contactFlg = ADMIN
		contactsMap[ADMIN] = make(map[string]interface{})
		return true
	case "Billing contact":
		*contactFlg = BILLING
		contactsMap[BILLING] = make(map[string]interface{})
		return true
	case "Tech contact":
		*contactFlg = TECH
		contactsMap[TECH] = make(map[string]interface{})
		return true
	}
	return false
}

func (tkw *TKTLDParser) handleNameServers(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Domain Nameservers" {
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

func (tkw *TKTLDParser) handleContactDetails(key, val string, contactFlg string, contactsMap map[string]map[string]interface{}) {
	if len(contactFlg) == 0 {
		return
	}

	if key == "Name" || key == "Organization" || key == "Phone" || key == "Fax" || key == "E-mail" ||
		key == "Address" || key == "City" || key == "Zipcode" || key == "Country" || key == "State" {
		ckey := mapContactKeys(tkContactKeyMap, strings.ToLower(key))
		if ckey == "street" {
			if _, ok := contactsMap[contactFlg][ckey]; !ok {
				contactsMap[contactFlg][ckey] = []string{}
			}
			contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
			return
		}
		contactsMap[contactFlg][ckey] = val
	}
}

func (tkw *TKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := tkw.parser.Do(rawtext, nil, tkMap)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}

		// Handle basic fields
		if tkw.handleBasicFields(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle contact sections
		if tkw.handleContactSection(key, &contactFlg, contactsMap) {
			continue
		}

		// Handle name servers
		if tkw.handleNameServers(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle contact details
		tkw.handleContactDetails(key, val, contactFlg, contactsMap)
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
