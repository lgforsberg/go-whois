package domain

import (
	"strings"
)

func itMapContactKeyValue(key string) string {
	if key == "Address" {
		return "street"
	}
	return strings.ToLower(key)
}

// ITTLDParser is a specialized parser for .it domain whois responses.
// It handles the specific format used by Registro.it, the Italian registry.
type ITTLDParser struct {
	parser IParser
}

func (itw *ITTLDParser) GetName() string {
	return "it"
}

// NewITTLDParser creates a new parser for .it domain whois responses.
// The parser is configured to handle Italian registry contact sections and field layouts.
func NewITTLDParser() *ITTLDParser {
	return &ITTLDParser{
		parser: NewParser(),
	}
}

func (itw *ITTLDParser) handleNameServers(lines []string, idx int, parsedWhois *ParsedWhois) {
	for i := 1; i <= maxNServer; i++ {
		ns := strings.TrimSpace(lines[idx+i])
		if len(ns) == 0 {
			break
		}
		parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
	}
}

func (itw *ITTLDParser) handleContactSection(key string, contactFlg *string, parsedWhois *ParsedWhois, contactsMap map[string]map[string]interface{}) {
	switch key {
	case "Registrar":
		*contactFlg = REGISTRAR
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
	case "Registrant":
		*contactFlg = REGISTRANT
		contactsMap[REGISTRANT] = make(map[string]interface{})
	case "Admin Contact":
		*contactFlg = ADMIN
		contactsMap[ADMIN] = make(map[string]interface{})
	case "Technical Contacts":
		*contactFlg = TECH
		contactsMap[TECH] = make(map[string]interface{})
	}
}

func (itw *ITTLDParser) handleContactDetails(key, val, contactFlg string, addressFlg *bool, parsedWhois *ParsedWhois, contactsMap map[string]map[string]interface{}) {
	if len(contactFlg) == 0 {
		return
	}
	if contactFlg == REGISTRAR {
		switch key {
		case "Name":
			parsedWhois.Registrar.Name = val
		case "Web":
			parsedWhois.Registrar.URL = val
		}
		return
	}
	ckey := itMapContactKeyValue(key)
	if ckey == "street" {
		if _, ok := contactsMap[contactFlg][ckey]; !ok {
			contactsMap[contactFlg][ckey] = []string{}
		}
		contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
		*addressFlg = true
		return
	}
	contactsMap[contactFlg][ckey] = val
}

func (itw *ITTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using Italian-specific pattern
	if strings.Contains(rawtext, "Status:             AVAILABLE") {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois, err := itw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	var addressFlg bool
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		key, val, err := getKeyValFromLine(line)

		if key == "Nameservers" {
			itw.handleNameServers(lines, idx, parsedWhois)
		} else {
			itw.handleContactSection(key, &contactFlg, parsedWhois, contactsMap)
		}

		if key == "Name" || key == "Organization" || key == "Address" || key == "" {
			itw.handleContactDetails(key, val, contactFlg, &addressFlg, parsedWhois, contactsMap)
		} else if err != nil && addressFlg && len(contactFlg) > 0 && len(key) > 0 {
			contactsMap[contactFlg]["street"] = append(contactsMap[contactFlg]["street"].([]string), key)
		} else {
			addressFlg = false
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
