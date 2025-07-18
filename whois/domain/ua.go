package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

var UAMap map[string]string = map[string]string{
	"abuse-email": "reg/abuse_contact_email",
	"abuse-phone": "reg/abuse_contact_phone",
	"url":         "reg/url",
}

var uaContactKeyMap = map[string]string{
	"person":           "name",
	"organization-loc": "organization",
	"e-mail":           "email",
	"address":          "street",
}

type UATLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (uaw *UATLDParser) GetName() string {
	return "ua"
}

func NewUATLDParser() *UATLDParser {
	return &UATLDParser{
		parser:   NewParser(),
		stopFunc: nil,
	}
}

func (uaw *UATLDParser) handleContactSection(key string, contactFlg *string, contactsMap map[string]map[string]interface{}) {
	switch key {
	case "% Registrant":
		*contactFlg = REGISTRANT
		contactsMap[REGISTRANT] = make(map[string]interface{})
	case "% Administrative Contacts":
		*contactFlg = ADMIN
		contactsMap[ADMIN] = make(map[string]interface{})
	case "% Technical Contacts":
		*contactFlg = TECH
		contactsMap[TECH] = make(map[string]interface{})
	}
}

func (uaw *UATLDParser) handleContactDetails(key, val, contactFlg string, contactsMap map[string]map[string]interface{}) {
	if len(contactFlg) == 0 {
		return
	}
	ckey := mapContactKeys(uaContactKeyMap, key)
	if ckey == "street" {
		if _, ok := contactsMap[contactFlg][ckey]; !ok {
			contactsMap[contactFlg][ckey] = []string{}
		}
		contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
		return
	}
	contactsMap[contactFlg][ckey] = val
}

func (uaw *UATLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized detection logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := uaw.parser.Do(rawtext, nil, UAMap)
	if err != nil {
		return nil, err
	}
	uniStatus := []string{}
	for _, s := range parsedWhois.Statuses {
		if !utils.StrInArray(s, uniStatus) {
			uniStatus = append(uniStatus, s)
		}
	}
	parsedWhois.Statuses = uniStatus

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}

		uaw.handleContactSection(key, &contactFlg, contactsMap)

		if key == "person" || key == "organization-loc" || key == "phone" || key == "fax" || key == "e-mail" || key == "address" {
			uaw.handleContactDetails(key, val, contactFlg, contactsMap)
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
