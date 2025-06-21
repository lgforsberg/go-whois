package utils

import (
	"strings"
	"time"
)

// WhoisTimeFmt is time format for CreatedDate, UpdatedDate and ExpiredDate
// Copied from domain package to avoid import cycle
const WhoisTimeFmt = "2006-01-02T15:04:05+00:00"

// ExtractValue extracts a value from a colon-separated line
// Pattern: strings.TrimSpace(line[strings.Index(line, ":")+1:])
func ExtractValue(line string) string {
	if idx := strings.Index(line, ":"); idx != -1 && idx+1 < len(line) {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// ExtractField extracts a field value from a line with a specific prefix
// Pattern: strings.TrimSpace(strings.TrimPrefix(line, prefix))
func ExtractField(line, prefix string) string {
	line = strings.TrimSpace(line)
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

// SkipLine determines if a line should be skipped (empty or comment)
// Pattern: line == "" || strings.HasPrefix(line, "%")
func SkipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "%")
}

// InitContact creates and returns a new Contact struct with default values
// Note: Returns map[string]string to avoid import cycle with domain package
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

// InitRegistrar creates and returns a new Registrar struct with default values
// Note: Returns map[string]string to avoid import cycle with domain package
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

// ParseDateField parses a date field from a line with a specific prefix
// Uses the standard WhoisTimeFmt format
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

// ParseNameServers extracts nameserver information from a slice of lines
// Handles common patterns like "nserver:", "nameserver:", etc.
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

// HandleNameserverField parses a nameserver field from a line with a configurable prefix
// Pattern: Check for nameserver prefix, extract field value, append to NameServers slice, return flow control
// Returns true if the line was processed as a nameserver field, false otherwise
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

// IsNameserverLine checks if a line contains nameserver information with a given prefix
// Pattern: Check if line starts with nameserver prefix
// Returns true if the line is a nameserver line, false otherwise
func IsNameserverLine(line, prefix string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, prefix)
}

// IsRegistrarLine checks if a line contains registrar information with a given prefix
// Pattern: Check if line starts with registrar prefix
// Returns true if the line is a registrar line, false otherwise
func IsRegistrarLine(line, prefix string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, prefix)
}

// IsContactSection checks if a line indicates a contact section
// Pattern: Check if line contains contact section keywords
// Returns true if the line indicates a contact section, false otherwise
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
