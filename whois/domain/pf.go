package domain

import (
	"regexp"
	"strings"
)

type PFTLDParser struct {
	parser IParser
}

var pfDomainRe = regexp.MustCompile(`Informations about '([^']+)'`)

func NewPFTLDParser() *PFTLDParser {
	return &PFTLDParser{
		parser: NewParser(),
	}
}

func (pfw *PFTLDParser) GetName() string {
	return "pf"
}

func (pfw *PFTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	if strings.Contains(rawtext, "Domain unknown") {
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	pfw.parseDomainLine(lines, parsedWhois)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "This is the PF") || strings.HasPrefix(line, "Informations about") {
			continue
		}

		if pfw.parseStatusDateNS(line, parsedWhois) {
			continue
		}

		if strings.Contains(line, " : ") {
			pfw.parseContactOrRegistrarField(line, parsedWhois)
		}
	}

	return parsedWhois, nil
}

func (pfw *PFTLDParser) parseDomainLine(lines []string, parsedWhois *ParsedWhois) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Informations about") {
			matches := pfDomainRe.FindStringSubmatch(line)
			if len(matches) == 2 {
				parsedWhois.DomainName = matches[1]
			}
			break
		}
	}
}

func (pfw *PFTLDParser) parseStatusDateNS(line string, parsedWhois *ParsedWhois) bool {
	switch {
	case strings.HasPrefix(line, "Status :"):
		status := strings.TrimSpace(strings.TrimPrefix(line, "Status :"))
		if status != "" {
			parsedWhois.Statuses = []string{status}
		}
		return true
	case strings.HasPrefix(line, "Created (JJ/MM/AAAA) :"):
		parsedWhois.CreatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Created (JJ/MM/AAAA) :"))
		return true
	case strings.HasPrefix(line, "Last renewed (JJ/MM/AAAA) :"):
		parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Last renewed (JJ/MM/AAAA) :"))
		return true
	case strings.HasPrefix(line, "Expire (JJ/MM/AAAA) :"):
		parsedWhois.ExpiredDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Expire (JJ/MM/AAAA) :"))
		return true
	case strings.HasPrefix(line, "Name server"):
		ns := strings.TrimSpace(strings.TrimPrefix(line, "Name server"))
		if idx := strings.Index(ns, ":"); idx != -1 {
			ns = strings.TrimSpace(ns[idx+1:])
			if ns != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		}
		return true
	}
	return false
}

func (pfw *PFTLDParser) parseContactOrRegistrarField(line string, parsedWhois *ParsedWhois) {
	parts := strings.SplitN(line, " : ", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	switch {
	case strings.HasPrefix(key, "Registrant"):
		pfw.assignContactField(parsedWhois, &parsedWhois.Contacts, "Registrant", key, value)
	case strings.HasPrefix(key, "Tech 1"):
		pfw.assignContactField(parsedWhois, &parsedWhois.Contacts, "Tech 1", key, value)
	case strings.HasPrefix(key, "Registrar"):
		pfw.assignRegistrarField(parsedWhois, key, value)
	}
}

func (pfw *PFTLDParser) assignContactField(parsedWhois *ParsedWhois, contacts **Contacts, contactType, key, value string) {
	if *contacts == nil {
		*contacts = &Contacts{}
	}
	var c **Contact
	switch contactType {
	case "Registrant":
		if (*contacts).Registrant == nil {
			(*contacts).Registrant = &Contact{}
		}
		c = &(*contacts).Registrant
	case "Tech 1":
		if (*contacts).Tech == nil {
			(*contacts).Tech = &Contact{}
		}
		c = &(*contacts).Tech
	default:
		return
	}
	fieldName := strings.TrimSpace(strings.TrimPrefix(key, contactType))
	switch fieldName {
	case "Compagnie Name":
		(*c).Organization = value
	case "Name":
		(*c).Name = value
	case "Email":
		(*c).Email = value
	case "Address":
		(*c).Street = append((*c).Street, value)
	case "Postal Code":
		(*c).Postal = value
	case "City":
		(*c).City = value
	case "Region / Island":
		(*c).State = value
	case "Country":
		(*c).Country = value
	}
}

func (pfw *PFTLDParser) assignRegistrarField(parsedWhois *ParsedWhois, key, value string) {
	if parsedWhois.Registrar == nil {
		parsedWhois.Registrar = &Registrar{}
	}
	fieldName := strings.TrimSpace(strings.TrimPrefix(key, "Registrar"))
	switch fieldName {
	case "Compagnie Name":
		parsedWhois.Registrar.Name = value
		// Other registrar fields are not stored
	}
}
