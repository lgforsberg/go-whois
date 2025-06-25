package domain

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	CONTACTS = "contacts"

	REGISTRAR = "registrar"

	REGISTRANT = "registrant"
	ADMIN      = "admin"
	TECH       = "tech"
	BILLING    = "billing"

	maxNServer = 20
	maxDStatus = 10
)

var dayReplacer = strings.NewReplacer("st", "", "nd", "", "rd", "", "th", "")

func mapRawtextKeyToStructKey(key string) string {
	if val, ok := defaultKeyMap[strings.ToLower(key)]; ok {
		return val
	}
	return ""
}

var defaultKeyMap map[string]string = map[string]string{
	"domain name":                            "domain",
	"domain":                                 "domain",
	"name server":                            "name_servers",
	"nserver":                                "name_servers",
	"nameserver":                             "name_servers",
	"nameservers":                            "name_servers",
	"creation date":                          "created_date",
	"created":                                "created_date",
	"created on":                             "created_date",
	"registered on":                          "created_date",
	"registration time":                      "created_date",
	"registered":                             "created_date",
	"updated date":                           "updated_date",
	"last updated":                           "updated_date",
	"last update":                            "updated_date",
	"modified":                               "updated_date",
	"updated":                                "updated_date",
	"last updated on":                        "updated_date",
	"last modified":                          "updated_date",
	"registry expiry date":                   "expired_date",
	"expires":                                "expired_date",
	"expire":                                 "expired_date",
	"expiration date":                        "expired_date",
	"expiry date":                            "expired_date",
	"expire date":                            "expired_date",
	"paid-till":                              "expired_date",
	"valid until":                            "expired_date",
	"registrar registration expiration date": "expired_date",
	"expiration time":                        "expired_date",
	"domain status":                          "statuses",
	"status":                                 "statuses",
	"dnssec":                                 "dnssec",
	"registrar iana id":                      "reg/iana_id",
	"registrar":                              "reg/name",
	"sponsoring registrar":                   "reg/name",
	"registrar name":                         "reg/name",
	"registrar abuse contact email":          "reg/abuse_contact_email",
	"registrar abuse contact phone":          "reg/abuse_contact_phone",
	"registrar url":                          "reg/url",
	"whois server":                           "reg/whois_server",
	"registrar whois server":                 "reg/whois_server",
	"registrant name":                        "c/registrant/name",
	"registrant email":                       "c/registrant/email",
	"registrant contact email":               "c/registrant/email",
	"registrant organization":                "c/registrant/organization",
	"registrant country":                     "c/registrant/country",
	"registrant city":                        "c/registrant/city",
	"registrant street":                      "c/registrant/street",
	"registrant state/province":              "c/registrant/state",
	"registrant postal code":                 "c/registrant/postal",
	"registrant phone":                       "c/registrant/phone",
	"registrant phoneExt":                    "c/registrant/phone_ext",
	"registrant fax":                         "c/registrant/fax",
	"registrant faxExt":                      "c/registrant/fax_ext",
	"admin name":                             "c/admin/name",
	"admin email":                            "c/admin/email",
	"admin organization":                     "c/admin/organization",
	"admin country":                          "c/admin/country",
	"admin city":                             "c/admin/city",
	"admin street":                           "c/admin/street",
	"admin state/province":                   "c/admin/state",
	"admin postal code":                      "c/admin/postal",
	"admin phone":                            "c/admin/phone",
	"admin phoneext":                         "c/admin/phone_ext",
	"admin fax":                              "c/admin/fax",
	"admin faxext":                           "c/admin/fax_ext",
	"tech name":                              "c/tech/name",
	"tech email":                             "c/tech/email",
	"tech organization":                      "c/tech/organization",
	"tech country":                           "c/tech/country",
	"tech city":                              "c/tech/city",
	"tech street":                            "c/tech/street",
	"tech state/province":                    "c/tech/state",
	"tech postal code":                       "c/tech/postal",
	"tech phone":                             "c/tech/phone",
	"tech phoneext":                          "c/tech/phone_ext",
	"tech fax":                               "c/tech/fax",
	"tech faxext":                            "c/tech/fax_ext",
	"billing name":                           "c/billing/name",
	"billing email":                          "c/billing/email",
	"billing organization":                   "c/billing/organization",
	"billing country":                        "c/billing/country",
	"billing city":                           "c/billing/city",
	"billing street":                         "c/billing/street",
	"billing state/province":                 "c/billing/state",
	"billing postal code":                    "c/billing/postal",
	"billing phone":                          "c/billing/phone",
	"billing phoneext":                       "c/billing/phone_ext",
	"billing fax":                            "c/billing/fax",
	"billing faxext":                         "c/billing/fax_ext",
}

var notFoundMsg = []string{
	"no data found",
	"no object found",
	"not found",
	"no match",
	"not registered",
	"no object found",
	"object does not exist",
	"nothing found",
	"no entries found",
	"but this server does not have", // whois.iana.org
}

// IParser is used to parse whois information when input is domain
type IParser interface {
	Do(string, func(string) bool, ...map[string]string) (*ParsedWhois, error)
}

// ITLDParser defines the interface for TLD-specific WHOIS parsers.
// Each TLD may have different parsing requirements and response formats.
type ITLDParser interface {
	GetParsedWhois(string) (*ParsedWhois, error)
	GetName() string
}

// NewTLDDomainParser return different parser for different TLD
// If adding new parser for specific TLDs, new case match should be added to this function
//
//	parser := NewTLDDomainParser(whois_server)
//	parsedWhois, err := parser.GetParsedWhois(rawtext)
func NewTLDDomainParser(whoisServer string) ITLDParser {
	// Map of whois servers to their corresponding parser constructors
	serverParserMap := map[string]func() ITLDParser{
		"whois.nic.ar":             func() ITLDParser { return NewARTLDParser() }, // ar
		"whois.amnic.net":          func() ITLDParser { return NewAMTLDParser() }, // am
		"whois.nic.as":             func() ITLDParser { return NewASTLDParser() }, // as
		"whois.nic.at":             func() ITLDParser { return NewATTLDParser() }, // at
		"whois.audns.net.au":       func() ITLDParser { return NewAUTLDParser() }, // au
		"whois.dns.be":             func() ITLDParser { return NewBETLDParser() }, // be
		"whois.nic.br":             func() ITLDParser { return NewBRTLDParser() }, // br
		"whois.nic.cz":             func() ITLDParser { return NewCZTLDParser() }, // cz
		"whois.eu":                 func() ITLDParser { return NewEUTLDParser() }, // eu
		"whois.nic.fr":             func() ITLDParser { return NewFRTLDParser() }, // fr
		"whois.fi":                 func() ITLDParser { return NewFITLDParser() }, // fi
		"whois.nic.ir":             func() ITLDParser { return NewIRTLDParser() }, // ir
		"whois.nic.it":             func() ITLDParser { return NewITTLDParser() }, // it
		"whois.domain-registry.nl": func() ITLDParser { return NewNLTLDParser() }, // nl
		"whois.dns.pl":             func() ITLDParser { return NewPLTLDParser() }, // pl
		"whois.dns.pt":             func() ITLDParser { return NewPTTLDParser() }, // pt
		"whois.ripn.net":           func() ITLDParser { return NewRUTLDParser() }, // ru
		"whois.sk-nic.sk":          func() ITLDParser { return NewSKTLDParser() }, // sk
		"whois.twnic.net":          func() ITLDParser { return NewTWTLDParser() }, // tw
		"whois.twnic.net.tw":       func() ITLDParser { return NewTWTLDParser() }, // tw
		"whois.nic.uk":             func() ITLDParser { return NewUKTLDParser() }, // uk
		"whois.ja.net":             func() ITLDParser { return NewUKTLDParser() }, // uk
		"whois.ua":                 func() ITLDParser { return NewUATLDParser() }, // ua
		"whois.net.ua":             func() ITLDParser { return NewUATLDParser() }, // ua
		"whois.in.ua":              func() ITLDParser { return NewUATLDParser() }, // ua
		"whois.denic.de":           func() ITLDParser { return NewDETLDParser() }, // de
		"whois.jprs.jp":            func() ITLDParser { return NewJPTLDParser() }, // jp
		"whois.cnnic.cn":           func() ITLDParser { return NewCNTLDParser() }, // cn
		"whois.dk-hostmaster.dk":   func() ITLDParser { return NewDKTLDParser() }, // dk
		"whois.iis.se":             func() ITLDParser { return NewSETLDParser() }, // se, nu
		"whois.iis.nu":             func() ITLDParser { return NewSETLDParser() }, // se, nu
		"whois.norid.no":           func() ITLDParser { return NewNOTLDParser() }, // no
		"whois.nic.aw":             func() ITLDParser { return NewAWTLDParser() }, // aw
		"whois.register.bg":        func() ITLDParser { return NewBGTLDParser() }, // bg
		"whois.nic.cl":             func() ITLDParser { return NewCLTLDParser() }, // cl
		"whois.nic.cr":             func() ITLDParser { return NewCRTLDParser() }, // cr
		"whois.eenet.ee":           func() ITLDParser { return NewEETLDParser() }, // ee
		"whois.channelisles.net":   func() ITLDParser { return NewGGTLDParser() }, // gg, je
		"whois.hkirc.hk":           func() ITLDParser { return NewHKTLDParser() }, // hk
		"whois.dns.hr":             func() ITLDParser { return NewHRTLDParser() }, // hr
		"whois.nic.hu":             func() ITLDParser { return NewHUTLDParser() }, // hu
		"whois.nic.im":             func() ITLDParser { return NewIMTLDParser() }, // im
		"whois.isnic.is":           func() ITLDParser { return NewISTLDParser() }, // is
		"whois.kr":                 func() ITLDParser { return NewKRTLDParser() }, // kr
		"whois.nic.kz":             func() ITLDParser { return NewKZTLDParser() }, // kz
		"whois.domreg.lt":          func() ITLDParser { return NewLTTLDParser() }, // lt
		"whois.dns.lu":             func() ITLDParser { return NewLUTLDParser() }, // lu
		"whois.nic.lv":             func() ITLDParser { return NewLVTLDParser() }, // lv
		"whois.nic.md":             func() ITLDParser { return NewMDTLDParser() }, // md
		"whois.marnet.mk":          func() ITLDParser { return NewMKTLDParser() }, // mk
		"whois.monic.mo":           func() ITLDParser { return NewMOTLDParser() }, // mo
		"whois.mx":                 func() ITLDParser { return NewMXTLDParser() }, // mx
		"whois.nic.pf":             func() ITLDParser { return NewPFTLDParser() }, // pf
		"whois.nic.qa":             func() ITLDParser { return NewQATLDParser() }, // qa
		"whois.rotld.ro":           func() ITLDParser { return NewROTLDParser() }, // ro
		"whois.rnids.rs":           func() ITLDParser { return NewRSTLDParser() }, // rs
		"whois.nic.sa":             func() ITLDParser { return NewSATLDParser() }, // sa
		"whois.arnes.si":           func() ITLDParser { return NewSITLDParser() }, // si
		"whois.nic.sm":             func() ITLDParser { return NewSMTLDParser() }, // sm
		"whois.nic.sn":             func() ITLDParser { return NewSNTLDParser() }, // sn
		"whois.tcinet.ru":          func() ITLDParser { return NewSUTLDParser() }, // su
		"whois.nic.tg":             func() ITLDParser { return NewTGTLDParser() }, // tg
		"whois.thnic.co.th":        func() ITLDParser { return NewTHTLDParser() }, // th
		"whois.nic.tm":             func() ITLDParser { return NewTMTLDParser() }, // tm
		"whois.ati.tn":             func() ITLDParser { return NewTNTLDParser() }, // tn
		"whois.nic.tr":             func() ITLDParser { return NewTRTLDParser() }, // tr
		"whois.tznic.or.tz":        func() ITLDParser { return NewTZTLDParser() }, // tz
		"whois.co.ug":              func() ITLDParser { return NewUGTLDParser() }, // ug
		"whois.cctld.uz":           func() ITLDParser { return NewUZTLDParser() }, // uz
		"whois.nic.ve":             func() ITLDParser { return NewVETLDParser() }, // ve
		"whois.vunic.vu":           func() ITLDParser { return NewVUTLDParser() }, // vu
	}

	// Special case for multiple servers sharing the same parser
	specialServerMap := map[string]func() ITLDParser{}

	// Check special cases first
	if parserFunc, exists := specialServerMap[whoisServer]; exists {
		return parserFunc()
	}

	// Check regular server map
	if parserFunc, exists := serverParserMap[whoisServer]; exists {
		return parserFunc()
	}

	// Default case
	return NewTLDParser()
}

// Parser implements the default WHOIS parser for domains.
// It uses a generic key-value parsing approach suitable for most TLD formats.
type Parser struct{}

// TLDParser wraps the default Parser with TLD-specific configuration.
// It provides a consistent interface for parsing while allowing customization of parsing behavior.
type TLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

// NewParser creates a new instance of the default WHOIS parser.
func NewParser() *Parser {
	return &Parser{}
}

// NewTLDParser creates a new TLD parser with default configuration.
// It uses a stop function that stops parsing when encountering lines starting with ">>>".
func NewTLDParser() *TLDParser {
	return &TLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, ">>>") },
	}
}

// GetName return name of TLDParser for logging
func (wtld *TLDParser) GetName() string {
	return "default"
}

// GetParsedWhois invoke Do in parser to parse rawtext
func (wtld *TLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found using centralized logic
	if CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	return wtld.parser.Do(rawtext, wtld.stopFunc)
}

// Do parse rawtext with DefaultKeyMap, stop parsing if stopFunc is given and return true
// If specKeyMaps is given, it will parse
func (wb *Parser) Do(rawtext string, stopFunc func(string) bool, specKeyMaps ...map[string]string) (*ParsedWhois, error) {
	wMap := make(map[string]interface{})

	parseLinesToWhoisMap(rawtext, stopFunc, specKeyMaps, wMap)

	parsedWhois, err := map2ParsedWhois(wMap)
	if err != nil {
		return nil, err
	}

	processDateFields(parsedWhois)

	sort.Strings(parsedWhois.NameServers)
	sort.Strings(parsedWhois.Statuses)
	return parsedWhois, nil
}

// parseLinesToWhoisMap parses lines and fills the whois map
func parseLinesToWhoisMap(rawtext string, stopFunc func(string) bool, specKeyMaps []map[string]string, wMap map[string]interface{}) {
	for _, line := range strings.Split(rawtext, "\n") {
		line = strings.TrimSpace(line)
		if IsCommentLine(line) {
			continue
		}
		if stopFunc != nil && stopFunc(line) {
			break
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		mapKeysToWhoisMap(key, val, specKeyMaps, wMap)
	}
}

// mapKeysToWhoisMap maps keys to the whois map using default and special key maps
func mapKeysToWhoisMap(key, val string, specKeyMaps []map[string]string, wMap map[string]interface{}) {
	if keyName := mapRawtextKeyToStructKey(key); len(keyName) > 0 {
		fillWhoisMap(wMap, keyName, val, false)
	}
	if len(specKeyMaps) > 0 {
		for _, specKeyMap := range specKeyMaps {
			if keyName, ok := specKeyMap[key]; ok {
				fillWhoisMap(wMap, keyName, val, true)
			}
		}
	}
}

// fillWhoisMap maps key name in raw text to whois json struct tag
func fillWhoisMap(wMap map[string]interface{}, keyName, val string, overwriteIfExist bool) {
	// Registrar
	if strings.HasPrefix(keyName, "reg/") {
		fillRegistrarInfo(wMap, keyName, val)
		return
	}

	// Contacts
	if strings.HasPrefix(keyName, "c/") {
		fillContactInfo(wMap, keyName, val)
		return
	}

	// Other fields
	fillOtherFields(wMap, keyName, val, overwriteIfExist)
}

func fillRegistrarInfo(wMap map[string]interface{}, keyName, val string) {
	if _, ok := wMap[REGISTRAR]; !ok {
		wMap[REGISTRAR] = make(map[string]string)
	}
	kn := strings.TrimLeft(keyName, "reg/")
	if regMap, ok := wMap[REGISTRAR].(map[string]string); ok {
		regMap[kn] = val
	}
}

func fillContactInfo(wMap map[string]interface{}, keyName, val string) {
	if _, ok := wMap[CONTACTS]; !ok {
		wMap[CONTACTS] = make(map[string]map[string]interface{})
	}

	for _, cKey := range []string{REGISTRANT, ADMIN, TECH, BILLING} {
		contactPrefix := "c/" + cKey + "/"
		if !strings.HasPrefix(keyName, contactPrefix) {
			continue
		}

		if contactsMap, ok := wMap[CONTACTS].(map[string]map[string]interface{}); ok {
			if _, ok := contactsMap[cKey]; !ok {
				contactsMap[cKey] = make(map[string]interface{})
			}
			contactFieldKey := keyName[len(contactPrefix):]
			fillContactField(contactsMap[cKey], contactFieldKey, val)
		}
	}
}

func fillContactField(contactMap map[string]interface{}, fieldKey, val string) {
	switch fieldKey {
	case "street":
		if _, ok := contactMap[fieldKey]; !ok {
			contactMap[fieldKey] = []string{}
		}
		if streetSlice, ok := contactMap[fieldKey].([]string); ok {
			contactMap[fieldKey] = append(streetSlice, val)
		}
	default:
		contactMap[fieldKey] = val
	}
}

func fillOtherFields(wMap map[string]interface{}, keyName, val string, overwriteIfExist bool) {
	switch keyName {
	case "statuses":
		fillStatusesField(wMap, val)
	case "name_servers":
		fillNameServersField(wMap, val)
	default:
		fillDefaultField(wMap, keyName, val, overwriteIfExist)
	}
}

func fillStatusesField(wMap map[string]interface{}, val string) {
	if _, ok := wMap["statuses"]; !ok {
		wMap["statuses"] = []string{}
	}

	// Trim link in status
	// E.g., clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
	// if contains ",", split by ","
	if strings.Contains(val, ",") {
		for _, status := range strings.Split(val, ",") {
			if statusSlice, ok := wMap["statuses"].([]string); ok {
				wMap["statuses"] = append(statusSlice, strings.TrimSpace(status))
			}
		}
		return
	}

	statusValue := strings.Split(val, " ")[0]
	if statusSlice, ok := wMap["statuses"].([]string); ok {
		wMap["statuses"] = append(statusSlice, statusValue)
	}
}

func fillNameServersField(wMap map[string]interface{}, val string) {
	if _, ok := wMap["name_servers"]; !ok {
		wMap["name_servers"] = []string{}
	}
	if nsSlice, ok := wMap["name_servers"].([]string); ok {
		wMap["name_servers"] = append(nsSlice, val)
	}
}

func fillDefaultField(wMap map[string]interface{}, keyName, val string, overwriteIfExist bool) {
	if overwriteIfExist {
		wMap[keyName] = val
	} else {
		if _, ok := wMap[keyName]; !ok {
			wMap[keyName] = val
		}
	}
}

func processDateFields(parsedWhois *ParsedWhois) {
	parsedWhois.CreatedDateRaw = parsedWhois.CreatedDate
	parsedWhois.UpdatedDateRaw = parsedWhois.UpdatedDate
	parsedWhois.ExpiredDateRaw = parsedWhois.ExpiredDate
	parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
}

func map2ParsedWhois(wMap map[string]interface{}) (*ParsedWhois, error) {
	// Marshal from map and unmarshal to Whois Struct
	jsoncontent, err := json.Marshal(wMap)
	if err != nil {
		return nil, err
	}
	w := ParsedWhois{}
	if err := json.Unmarshal(jsoncontent, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func map2ParsedContacts(cMap map[string]map[string]interface{}) (*Contacts, error) {
	jsoncontent, err := json.Marshal(cMap)
	if err != nil {
		return nil, err
	}
	w := Contacts{}
	if err := json.Unmarshal(jsoncontent, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func mapContactKeys(cKeyMap map[string]string, key string) string {
	if val, ok := cKeyMap[key]; ok {
		return val
	}
	return key
}

// FoundByKey return value of key from rawtext
// E.g., FoundByKey("whois server", "whois server: whois.nic.aaa") = whois.nic.aaa
func FoundByKey(key, rawtext string) string {
	keyPlusColon := key + ":"
	if startIdx := strings.Index(rawtext, keyPlusColon); startIdx != -1 {
		startIdx += len(keyPlusColon)
		if endIdx := strings.Index(rawtext[startIdx:], "\n"); endIdx != -1 {
			return strings.TrimSpace(rawtext[startIdx : startIdx+endIdx])
		}
	}
	return ""
}

// WhoisNotFound check if rawtext contains not found keywords
func WhoisNotFound(rawtext string) bool {
	for _, notFoundMsg := range notFoundMsg {
		if strings.Contains(strings.ToLower(rawtext), notFoundMsg) {
			return true
		}
	}
	return false
}

func getKeyValFromLine(line string) (key, val string, err error) {
	line = strings.TrimSpace(line)
	kw := strings.SplitN(line, ":", 2)
	if len(kw) < 2 {
		return line, "", errors.New("not valid line")
	}
	return strings.TrimSpace(kw[0]), strings.TrimSpace(kw[1]), nil
}

// IsCommentLine checks if a line is a comment in WHOIS output.
// Comment lines typically start with '%' or '*' characters.
func IsCommentLine(line string) bool {
	return strings.HasPrefix(line, "%") || strings.HasPrefix(line, "*")
}

// SetDomainAvailabilityStatus sets the appropriate status for domain availability
// In v2.0.0: Uses single "not_found" status for consistent behavior across all TLDs
// isAvailable: true = domain is available for registration (not found)
// isAvailable: false = domain is registered or restricted
func SetDomainAvailabilityStatus(parsedWhois *ParsedWhois, isAvailable bool) {
	if parsedWhois == nil {
		return
	}

	if isAvailable {
		// v2.0.0: Use single "not_found" status for clean, consistent behavior
		parsedWhois.Statuses = []string{"not_found"}
	}
	// For registered domains, keep existing status behavior
	// The calling parser should set appropriate registered status
}

// CheckDomainAvailability centralizes "not found" pattern detection logic
func CheckDomainAvailability(rawtext string) bool {
	// Check common "not found" patterns across all TLDs
	notFoundPatterns := []string{
		"not found",
		"no match",
		"not registered",
		"no data found",
		"no object found",
		"object does not exist",
		"nothing found",
		"no entries found",
		"domain not found",
		"no matching record",
		"not available",
		"domain unknown",
		"no information available",
		"% no match for",
		"%% not found",
		"status: available",
		"status:             available",
		" is free",
		"no found",
		"this domain name has not been registered",
		"available for registration",
	}

	lowerRawtext := strings.ToLower(rawtext)
	for _, pattern := range notFoundPatterns {
		if strings.Contains(lowerRawtext, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}
