package domain

import (
	"sort"
	"strings"
)

type EUParser struct{}

type EUTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewEUTLDParser() *EUTLDParser {
	return &EUTLDParser{
		parser: NewParser(),
	}
}

func (euw *EUTLDParser) GetName() string {
	return "eu"
}

func (euw *EUTLDParser) handleBasicFields(key, val string, parsedWhois *ParsedWhois) bool {
	if key == "Domain" {
		parsedWhois.DomainName = val
		return true
	}
	return false
}

func (euw *EUTLDParser) handleContactSection(key string, contactFlg *string, parsedWhois *ParsedWhois, contactsMap map[string]map[string]interface{}) bool {
	switch key {
	case "Registrar":
		*contactFlg = REGISTRAR
		if parsedWhois.Registrar == nil {
			parsedWhois.Registrar = &Registrar{}
		}
		return true
	case "Technical":
		*contactFlg = TECH
		contactsMap[TECH] = make(map[string]interface{})
		return true
	}
	return false
}

func (euw *EUTLDParser) handleNameServers(key string, lines []string, idx int, parsedWhois *ParsedWhois) bool {
	if key == "Name servers" {
		for i := 1; i <= maxNServer; i++ {
			ns := strings.TrimSpace(lines[idx+i])
			if len(ns) == 0 {
				break
			}
			if nss := strings.Split(ns, " "); len(nss) > 1 {
				// sometimes ns contains ip. E.g., ns1.onlinecasinos24.eu (217.182.6.84)
				ns = nss[0]
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
		}
		return true
	}
	return false
}

func (euw *EUTLDParser) handleContactDetails(key, val string, contactFlg string, parsedWhois *ParsedWhois, contactsMap map[string]map[string]interface{}) {
	if len(contactFlg) == 0 {
		return
	}

	if contactFlg == REGISTRAR {
		switch key {
		case "Name":
			parsedWhois.Registrar.Name = val
		case "Website":
			parsedWhois.Registrar.URL = val
		}
		return
	}

	if contactFlg == TECH {
		switch key {
		case "Organization", "Organisation":
			contactsMap[TECH]["organization"] = val
		case "Email":
			contactsMap[TECH]["email"] = val
		}
	}
}

func (euw *EUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")
	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	for idx, line := range lines {
		key, val, _ := getKeyValFromLine(line)

		// Handle basic fields
		if euw.handleBasicFields(key, val, parsedWhois) {
			continue
		}

		// Handle contact sections
		if euw.handleContactSection(key, &contactFlg, parsedWhois, contactsMap) {
			continue
		}

		// Handle name servers
		if euw.handleNameServers(key, lines, idx, parsedWhois) {
			continue
		}

		// Handle contact details
		euw.handleContactDetails(key, val, contactFlg, parsedWhois, contactsMap)
	}
	sort.Strings(parsedWhois.NameServers)
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
