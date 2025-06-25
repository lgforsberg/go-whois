package domain

import (
	"regexp"
	"strings"
)

// VUTLDParser represents the parser for .vu TLD
type VUTLDParser struct {
	parser IParser
}

// NewVUTLDParser creates a new VUTLDParser
func NewVUTLDParser() *VUTLDParser {
	return &VUTLDParser{
		parser: NewParser(),
	}
}

// GetName returns the name of the parser
func (p *VUTLDParser) GetName() string {
	return "vu"
}

// GetParsedWhois parses the whois response for .vu domains
func (p *VUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if strings.Contains(rawtext, "is not valid!") {
		parsedWhois := &ParsedWhois{
			DomainName: extractDomainFromInvalid(rawtext),
		}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	// Use default parser with custom key mappings
	keyMap := map[string]string{
		"First Name:":   "c/registrant/name",
		"Last Name:":    "c/registrant/name",
		"Adress:":       "c/registrant/street",
		"City:":         "c/registrant/city",
		"Country:":      "c/registrant/country",
		"Date Created:": "created_date",
		"Expiry date:":  "expired_date",
	}

	parsed, err := p.parser.Do(rawtext, func(line string) bool {
		return strings.HasPrefix(line, "#") && strings.Contains(line, "mywhois")
	}, keyMap)

	if err != nil {
		return nil, err
	}

	// Extract nameservers from DNS servers lines
	parsed.NameServers = extractNameserversFromDNS(rawtext)

	// Manually extract dates if not already set
	if parsed.CreatedDateRaw == "" {
		parsed.CreatedDateRaw = extractField(rawtext, "Date Created:")
	}
	if parsed.ExpiredDateRaw == "" {
		parsed.ExpiredDateRaw = extractField(rawtext, "Expiry date:")
	}

	// Ensure contacts are created
	if parsed.Contacts == nil {
		parsed.Contacts = &Contacts{}
	}
	if parsed.Contacts.Registrant == nil {
		parsed.Contacts.Registrant = &Contact{}
	}

	// Combine first and last name for registrant
	firstName := extractField(rawtext, "First Name:")
	lastName := extractField(rawtext, "Last Name:")
	if firstName != "" || lastName != "" {
		parsed.Contacts.Registrant.Name = strings.TrimSpace(firstName + " " + lastName)
	}

	// Set other contact fields
	if parsed.Contacts.Registrant.Street == nil {
		parsed.Contacts.Registrant.Street = []string{}
	}
	address := extractField(rawtext, "Adress:")
	if address != "" {
		parsed.Contacts.Registrant.Street = []string{address}
	}

	city := extractField(rawtext, "City:")
	if city != "" {
		parsed.Contacts.Registrant.City = city
	}

	country := extractField(rawtext, "Country:")
	if country != "" {
		parsed.Contacts.Registrant.Country = country
	}

	return parsed, nil
}

// extractDomainFromInvalid extracts domain name from "not valid" message
func extractDomainFromInvalid(rawtext string) string {
	re := regexp.MustCompile(`The domain ([^\s]+)\s+is not valid!`)
	matches := re.FindStringSubmatch(rawtext)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractNameserversFromDNS extracts nameservers from DNS servers lines
func extractNameserversFromDNS(rawtext string) []string {
	var nameservers []string
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS servers") {
			// Extract the nameserver part (before the IP address)
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				nsPart := strings.TrimSpace(parts[1])
				// Extract just the hostname part before the IP
				nsParts := strings.Fields(nsPart)
				if len(nsParts) > 0 {
					ns := strings.TrimSpace(nsParts[0])
					// Remove trailing dot if present
					ns = strings.TrimSuffix(ns, ".")
					if ns != "" {
						nameservers = append(nameservers, ns)
					}
				}
			}
		}
	}

	return nameservers
}

// extractField extracts a field value from the raw text
func extractField(rawtext, fieldName string) string {
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, fieldName) {
			value := strings.TrimSpace(strings.TrimPrefix(line, fieldName))
			return value
		}
	}

	return ""
}
