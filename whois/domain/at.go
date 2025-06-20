package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	ATTimeFmt = "20060102 15:04:05"
)

var ATMap map[string]string = map[string]string{
	"registrant": "c/registrant/id",
	"tech-c":     "c/tech/id",
}

var atContactKeyMap = map[string]string{
	"personname":     "name",
	"e-mail":         "email",
	"street address": "street",
	"postal code":    "postal",
	"fax-no":         "fax",
}

type ATTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (atw *ATTLDParser) GetName() string {
	return "at"
}

func NewATTLDParser() *ATTLDParser {
	return &ATTLDParser{
		parser: NewParser(),
	}
}

func (atw *ATTLDParser) handleRegistrarField(key, val string, parsedWhois *ParsedWhois) bool {
	if key == "registrar" {
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		parsedWhois.Registrar.Name = val
		return true
	}
	return false
}

func (atw *ATTLDParser) handleDateField(key, val string, parsedWhois *ParsedWhois, updateFlg *bool) bool {
	if key == "changed" && !*updateFlg {
		parsedWhois.UpdatedDateRaw = val
		*updateFlg = true
		return true
	}
	return false
}

func (atw *ATTLDParser) handleContactIDField(key, val string, parsedWhois *ParsedWhois) bool {
	if key == "tech-c" || key == "registrant" {
		if val == "<data not disclosed>" {
			return true
		}
		switch key {
		case "tech-c":
			parsedWhois.Contacts.Tech.ID = val
		case "registrant":
			parsedWhois.Contacts.Registrant.ID = val
		}
		return true
	}
	return false
}

func (atw *ATTLDParser) handleContactField(key, val string, tmpContact *map[string]interface{}, contactsMap map[string]map[string]interface{}, parsedWhois *ParsedWhois) bool {
	switch key {
	case "nic-hdl":
		if val == parsedWhois.Contacts.Registrant.ID {
			contactsMap[REGISTRANT] = *tmpContact
		}
		if val == parsedWhois.Contacts.Tech.ID {
			contactsMap[TECH] = *tmpContact
		}
		return true
	case "personname", "organization", "street address", "postal code", "city",
		"country", "phone", "e-mail", "fax-no":
		if key == "personname" {
			*tmpContact = make(map[string]interface{})
		}
		ckey := mapContactKeys(atContactKeyMap, key)
		if ckey == "street" {
			if _, ok := (*tmpContact)[ckey]; !ok {
				(*tmpContact)[ckey] = []string{}
			}
			(*tmpContact)[ckey] = append((*tmpContact)[ckey].([]string), val)
			return true
		}
		(*tmpContact)[ckey] = val
		return true
	}
	return false
}

func (atw *ATTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := atw.parser.Do(rawtext, nil, ATMap)
	if err != nil {
		return nil, err
	}

	contactsMap := map[string]map[string]interface{}{}
	var tmpContact map[string]interface{}
	var updateFlg bool
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}

		// Handle registrar field
		if atw.handleRegistrarField(key, val, parsedWhois) {
			continue
		}

		// Handle date field
		if atw.handleDateField(key, val, parsedWhois, &updateFlg) {
			continue
		}

		// Handle contact ID fields
		if atw.handleContactIDField(key, val, parsedWhois) {
			continue
		}

		// Handle contact fields
		atw.handleContactField(key, val, &tmpContact, contactsMap, parsedWhois)
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	// Parsed Time again since it has a weird format
	parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(parsedWhois.UpdatedDateRaw, ATTimeFmt, WhoisTimeFmt)
	return parsedWhois, err
}
