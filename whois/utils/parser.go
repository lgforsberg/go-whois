package utils

import (
	"strings"
	"time"
)

// WhoisTimeFmt is time format for CreatedDate, UpdatedDate and ExpiredDate
// Copied from domain package to avoid import cycle
const WhoisTimeFmt = "2006-01-02T15:04:05+00:00"

// ExtractValue extracts the value portion from a colon-separated line.
// It handles both "key: value" and "key:value" formats.
func ExtractValue(line string) string {
	if idx := strings.Index(line, ":"); idx != -1 && idx+1 < len(line) {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// ExtractField extracts a field value that comes after a specific prefix.
// This is commonly used for parsing nameserver and other prefixed fields.
func ExtractField(line, prefix string) string {
	line = strings.TrimSpace(line)
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

// SkipLine determines if a line should be skipped during parsing.
// It returns true for empty lines and comments starting with %.
func SkipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "%")
}

// InitContact creates a new contact map with default empty values.
// This is used as a template for parsing contact information.
func InitContact() map[string]string {
	return map[string]string{
		"id":           "",
		"name":         "",
		"organization": "",
		"email":        "",
		"phone":        "",
		"fax":          "",
		"country":      "",
		"city":         "",
		"state":        "",
		"postal":       "",
	}
}

// InitRegistrar creates a new registrar map with default empty values.
// This is used as a template for parsing registrar information.
func InitRegistrar() map[string]string {
	return map[string]string{
		"iana_id":             "",
		"name":                "",
		"abuse_contact_email": "",
		"abuse_contact_phone": "",
		"whois_server":        "",
		"url":                 "",
	}
}

// ParseDateField parses a date field from a line with the given prefix.
// Returns nil if the date cannot be parsed or if the line doesn't match the prefix.
func ParseDateField(line, prefix string) *time.Time {
	value := ExtractField(line, prefix)
	if value == "" {
		return nil
	}

	// Try parsing with the standard WhoisTimeFmt format
	if t, err := time.Parse(WhoisTimeFmt, value); err == nil {
		return &t
	}

	// Try parsing with common alternative formats
	formats := []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"02-Jan-2006",
		"2006.01.02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return &t
		}
	}

	return nil
}

// ParseNameServers extracts name server entries from an array of lines.
// It looks for lines that appear to contain nameserver information.
func ParseNameServers(lines []string) []string {
	var nameservers []string
	prefixes := []string{"nserver:", "nameserver:", "name server:"}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if SkipLine(line) {
			continue
		}

		lineLower := strings.ToLower(line)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lineLower, prefix) {
				// Find the actual prefix in the original line (case-insensitive match)
				actualPrefix := line[:len(prefix)]
				ns := ExtractField(line, actualPrefix)
				if ns != "" {
					nameservers = append(nameservers, ns)
				}
				break
			}
		}
	}

	return nameservers
}

// HandleNameserverField processes a nameserver field and adds it to the nameservers slice.
// Returns true if the line was processed as a nameserver field.
func HandleNameserverField(line string, prefix string, nameservers *[]string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, prefix) {
		return false
	}

	ns := ExtractField(line, prefix)
	if ns != "" {
		*nameservers = append(*nameservers, ns)
		return true
	}
	return false
}

// IsNameserverLine checks if a line contains nameserver information with the given prefix.
func IsNameserverLine(line, prefix string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, prefix)
}

// IsRegistrarLine checks if a line contains registrar information with the given prefix.
func IsRegistrarLine(line, prefix string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, prefix)
}

// IsContactSection determines if a line indicates the start of a contact section.
// It looks for common contact section headers in whois responses.
func IsContactSection(line string) bool {
	line = strings.TrimSpace(line)
	contactKeywords := []string{
		"registrant:", "administrative contact:", "technical contact:",
		"admin contact:", "tech contact:", "billing contact:",
	}

	lineLower := strings.ToLower(line)
	for _, keyword := range contactKeywords {
		if strings.HasPrefix(lineLower, keyword) {
			return true
		}
	}
	return false
}
