package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
)

// VETLDParser represents the parser for .ve TLD
type VETLDParser struct {
	parser IParser
}

// NewVETLDParser creates a new VETLDParser
func NewVETLDParser() *VETLDParser {
	return &VETLDParser{
		parser: NewParser(),
	}
}

// GetName returns the name of the parser
func (p *VETLDParser) GetName() string {
	return "ve"
}

// GetParsedWhois parses the whois response for .ve domains
func (p *VETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	// Check for Venezuela-specific not found pattern and centralized patterns
	if strings.Contains(rawtext, "%ERROR:101: no entries found") || CheckDomainAvailability(rawtext) {
		parsedWhois := &ParsedWhois{}
		SetDomainAvailabilityStatus(parsedWhois, true)
		return parsedWhois, nil
	}

	// Use default parser with custom key mappings
	keyMap := map[string]string{
		"domain:":     "domain_name",
		"registrar:":  "registrar",
		"registered:": "created_date",
		"changed:":    "updated_date",
		"expire:":     "expired_date",
		"updated:":    "updated_date",
	}

	parsed, err := p.parser.Do(rawtext, func(line string) bool {
		return strings.HasPrefix(line, "%") && strings.Contains(line, "Timestamp:")
	}, keyMap)

	if err != nil {
		return nil, err
	}

	// Extract nameservers from nsset sections
	parsed.NameServers = extractNameserversFromNSSET(rawtext)

	// Extract status manually to avoid splitting
	parsed.Statuses = extractStatus(rawtext)

	// Manually extract changed field if not already set
	if parsed.UpdatedDateRaw == "" {
		parsed.UpdatedDateRaw = extractChangedField(rawtext)
	}

	return parsed, nil
}

// extractStatus extracts status without splitting on spaces
func extractStatus(rawtext string) []string {
	var statuses []string
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "status:") {
			status := utils.ExtractField(line, "status:")
			if status != "" {
				statuses = append(statuses, status)
			}
		}
	}

	return statuses
}

// extractNameserversFromNSSET extracts nameservers from nsset sections
func extractNameserversFromNSSET(rawtext string) []string {
	var nameservers []string
	lines := strings.Split(rawtext, "\n")

	inNSSET := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if we're entering an nsset section
		if strings.HasPrefix(line, "nsset:") {
			inNSSET = true
			continue
		}

		// Check if we're leaving the nsset section
		if inNSSET && (strings.HasPrefix(line, "contact:") || strings.HasPrefix(line, "keyset:") || strings.HasPrefix(line, "domain:")) {
			inNSSET = false
			continue
		}

		// Extract nameserver from nserver lines
		if inNSSET && strings.HasPrefix(line, "nserver:") {
			// Extract the nameserver part (before the IP address)
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ns := strings.TrimSpace(parts[1])
				// Remove trailing dot if present
				ns = strings.TrimSuffix(ns, ".")
				if ns != "" {
					nameservers = append(nameservers, ns)
				}
			}
		}
	}

	return nameservers
}

// extractChangedField extracts the changed field manually
func extractChangedField(rawtext string) string {
	lines := strings.Split(rawtext, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "changed:") {
			changed := utils.ExtractField(line, "changed:")
			return changed
		}
	}

	return ""
}
