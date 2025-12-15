package domain

import (
	"regexp"
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	// eduTimeFmt is the date format used by EDUCAUSE WHOIS responses.
	// Example: 24-Apr-1985, 15-Jan-2025, 31-Jul-2027
	eduTimeFmt = "02-Jan-2006"
)

// EDUTLDParser is a specialized parser for .edu domain whois responses.
// It handles the specific format used by EDUCAUSE, the registry for .edu domains.
// The EDUCAUSE format uses:
//   - Tab-indented multi-line contact blocks
//   - Date format: DD-Mon-YYYY (e.g., 24-Apr-1985)
//   - "Domain record activated/updated/expires" date labels
type EDUTLDParser struct{}

// NewEDUTLDParser creates a new parser for .edu domain whois responses.
// The parser handles EDUCAUSE-specific formatting including multi-line
// contact blocks and the unique date field labels.
func NewEDUTLDParser() *EDUTLDParser {
	return &EDUTLDParser{}
}

func (p *EDUTLDParser) GetName() string {
	return "edu"
}

// GetParsedWhois parses a raw EDUCAUSE WHOIS response into structured data.
func (p *EDUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check if domain is not found
	if p.isNotFound(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	var currentSection string
	var contactLines []string

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmedLine := strings.TrimSpace(line)

		// Check for section headers (not indented, end with colon)
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			// Process any accumulated contact lines from previous section
			if len(contactLines) > 0 {
				p.parseContactBlock(currentSection, contactLines, parsedWhois)
				contactLines = nil
			}

			// Parse domain name
			if strings.HasPrefix(trimmedLine, "Domain Name:") {
				parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "Domain Name:"))
				currentSection = ""
				continue
			}

			// Parse dates
			if p.parseDateLine(trimmedLine, parsedWhois) {
				currentSection = ""
				continue
			}

			// Check for section headers
			if trimmedLine == "Registrant:" {
				currentSection = "registrant"
				continue
			}
			if trimmedLine == "Administrative Contact:" {
				currentSection = "admin"
				continue
			}
			if trimmedLine == "Technical Contact:" {
				currentSection = "tech"
				continue
			}
			if trimmedLine == "Name Servers:" {
				currentSection = "nameservers"
				continue
			}

			currentSection = ""
		} else if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "  ") {
			// Indented line - belongs to current section
			content := strings.TrimSpace(line)
			if content == "" {
				continue
			}

			switch currentSection {
			case "registrant", "admin", "tech":
				contactLines = append(contactLines, content)
			case "nameservers":
				parsedWhois.NameServers = append(parsedWhois.NameServers, strings.ToLower(content))
			}
		}
	}

	// Process any remaining contact lines
	if len(contactLines) > 0 {
		p.parseContactBlock(currentSection, contactLines, parsedWhois)
	}

	return parsedWhois, nil
}

// isNotFound checks if the WHOIS response indicates domain not found.
func (p *EDUTLDParser) isNotFound(rawtext string) bool {
	notFoundPatterns := []string{
		"No Match",
		"NO MATCH",
		"No match",
		"NOT FOUND",
		"Not found",
	}
	for _, pattern := range notFoundPatterns {
		if strings.Contains(rawtext, pattern) {
			return true
		}
	}
	return false
}

// parseDateLine parses date fields from the EDUCAUSE format.
func (p *EDUTLDParser) parseDateLine(line string, parsedWhois *ParsedWhois) bool {
	// EDUCAUSE uses format like: "Domain record activated:    24-Apr-1985"
	// The spacing between label and value varies

	switch {
	case strings.HasPrefix(line, "Domain record activated:"):
		dateStr := extractDateValue(line, "Domain record activated:")
		parsedWhois.CreatedDateRaw = dateStr
		parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(dateStr, eduTimeFmt, WhoisTimeFmt)
		return true

	case strings.HasPrefix(line, "Domain record last updated:"):
		dateStr := extractDateValue(line, "Domain record last updated:")
		parsedWhois.UpdatedDateRaw = dateStr
		parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(dateStr, eduTimeFmt, WhoisTimeFmt)
		return true

	case strings.HasPrefix(line, "Domain expires:"):
		dateStr := extractDateValue(line, "Domain expires:")
		parsedWhois.ExpiredDateRaw = dateStr
		parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(dateStr, eduTimeFmt, WhoisTimeFmt)
		return true
	}

	return false
}

// extractDateValue extracts the date value after a label, handling variable whitespace.
func extractDateValue(line, prefix string) string {
	value := strings.TrimPrefix(line, prefix)
	return strings.TrimSpace(value)
}

// parseContactBlock parses a multi-line contact block into structured contact data.
// EDUCAUSE contact format example:
//
//	UCLA
//	Office of the Secretary of the Regents
//	1111 Franklin Street, 12th Floor
//	Oakland, CA 94607
//	USA
//	+1.3107949061
//	email@example.edu
func (p *EDUTLDParser) parseContactBlock(section string, lines []string, parsedWhois *ParsedWhois) {
	if len(lines) == 0 {
		return
	}

	contact := &Contact{}

	// Regular expressions for detecting specific field types
	phoneRegex := regexp.MustCompile(`^\+?[0-9][0-9.\-() ]+$`)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	var addressLines []string

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// First line is typically the name (person or organization)
		if i == 0 {
			contact.Name = line
			continue
		}

		// Check if it's a phone number
		if phoneRegex.MatchString(line) {
			contact.Phone = line
			continue
		}

		// Check if it's an email
		if emailRegex.MatchString(line) {
			contact.Email = line
			continue
		}

		// Check if it's a country code (2-3 letter uppercase, common country names)
		if isCountry(line) {
			contact.Country = line
			continue
		}

		// Otherwise, it's part of the address/organization
		addressLines = append(addressLines, line)
	}

	// Process address lines
	if len(addressLines) > 0 {
		// First address line is often the organization/department
		if contact.Organization == "" && len(addressLines) > 0 {
			contact.Organization = addressLines[0]
			addressLines = addressLines[1:]
		}

		// Look for city/state/zip pattern in remaining lines
		for i, addr := range addressLines {
			if parsed := parseCityStateZip(addr); parsed != nil {
				contact.City = parsed.city
				contact.State = parsed.state
				contact.Postal = parsed.zip
				// Remove this line from street
				addressLines = append(addressLines[:i], addressLines[i+1:]...)
				break
			}
		}

		// Remaining lines are street address
		if len(addressLines) > 0 {
			contact.Street = addressLines
		}
	}

	// Assign contact to appropriate field
	if parsedWhois.Contacts == nil {
		parsedWhois.Contacts = &Contacts{}
	}

	switch section {
	case "registrant":
		parsedWhois.Contacts.Registrant = contact
	case "admin":
		parsedWhois.Contacts.Admin = contact
	case "tech":
		parsedWhois.Contacts.Tech = contact
	}
}

// cityStateZip holds parsed city/state/zip components.
type cityStateZip struct {
	city  string
	state string
	zip   string
}

// parseCityStateZip attempts to parse a line in "City, ST ZIP" format.
func parseCityStateZip(line string) *cityStateZip {
	// Pattern: "City, ST 12345" or "City, ST 12345-6789"
	pattern := regexp.MustCompile(`^(.+),\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)$`)
	if matches := pattern.FindStringSubmatch(line); matches != nil {
		return &cityStateZip{
			city:  strings.TrimSpace(matches[1]),
			state: matches[2],
			zip:   matches[3],
		}
	}
	return nil
}

// isCountry checks if a string looks like a country identifier.
func isCountry(s string) bool {
	// Common country names and codes
	countries := map[string]bool{
		"USA": true, "US": true, "UNITED STATES": true,
		"UK": true, "UNITED KINGDOM": true, "GB": true,
		"CANADA": true, "CA": true,
		"AUSTRALIA": true, "AU": true,
		"GERMANY": true, "DE": true,
		"FRANCE": true, "FR": true,
		"JAPAN": true, "JP": true,
		"CHINA": true, "CN": true,
		"INDIA": true, "IN": true,
		"BRAZIL": true, "BR": true,
		"MEXICO": true, "MX": true,
		"SPAIN": true, "ES": true,
		"ITALY": true, "IT": true,
		"NETHERLANDS": true, "NL": true,
		"SWEDEN": true, "SE": true,
		"NORWAY": true, "NO": true,
		"FINLAND": true, "FI": true,
		"DENMARK": true, "DK": true,
		"SWITZERLAND": true, "CH": true,
		"AUSTRIA": true, "AT": true,
		"BELGIUM": true, "BE": true,
		"IRELAND": true, "IE": true,
		"NEW ZEALAND": true, "NZ": true,
		"SINGAPORE": true, "SG": true,
		"HONG KONG": true, "HK": true,
		"SOUTH KOREA": true, "KR": true,
		"TAIWAN": true, "TW": true,
		"ISRAEL": true, "IL": true,
		"SOUTH AFRICA": true, "ZA": true,
		"ARGENTINA": true, "AR": true,
		"CHILE": true, "CL": true,
		"COLOMBIA": true, "CO": true,
		"PERU": true, "PE": true,
		"PUERTO RICO": true, "PR": true,
	}
	return countries[strings.ToUpper(s)]
}
