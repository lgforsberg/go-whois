package domain

import (
	"strings"
)

type SATLDParser struct {
	parser IParser
}

func NewSATLDParser() *SATLDParser {
	return &SATLDParser{
		parser: NewParser(),
	}
}

func (s *SATLDParser) GetName() string {
	return "sa"
}

func (s *SATLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered domains
	for _, line := range lines {
		if strings.Contains(line, "No Match for") {
			parsedWhois.Statuses = []string{"free"}
			return parsedWhois, nil
		}
	}

	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Registrant:") {
			currentSection = "registrant"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Registrant == nil {
				parsedWhois.Contacts.Registrant = &Contact{}
			}
		} else if strings.HasPrefix(line, "Administrative Contact:") {
			currentSection = "admin"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Admin == nil {
				parsedWhois.Contacts.Admin = &Contact{}
			}
		} else if strings.HasPrefix(line, "Technical Contact:") {
			currentSection = "tech"
			if parsedWhois.Contacts == nil {
				parsedWhois.Contacts = &Contacts{}
			}
			if parsedWhois.Contacts.Tech == nil {
				parsedWhois.Contacts.Tech = &Contact{}
			}
		} else if strings.HasPrefix(line, "Name Servers:") {
			currentSection = "nameservers"
		} else if strings.HasPrefix(line, "DNSSEC:") {
			parsedWhois.Dnssec = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC:"))
		} else if strings.HasPrefix(line, "DS Records:") {
			currentSection = "dsrecords"
		} else if currentSection == "nameservers" && line != "" {
			// Parse nameserver lines (can include IP addresses in parentheses)
			ns := line
			if idx := strings.Index(ns, " ("); idx != -1 {
				ns = strings.TrimSpace(ns[:idx])
			}
			if ns != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		} else if currentSection == "dsrecords" && line != "" {
			// DS records are not stored in the ParsedWhois struct, so we skip them
			continue
		} else if currentSection != "" && line != "" {
			// Handle contact information lines
			switch currentSection {
			case "registrant":
				c := parsedWhois.Contacts.Registrant
				if c.Organization == "" {
					c.Organization = line
				} else if strings.HasPrefix(line, "Address:") {
					// Extract address content after "Address:"
					address := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
					if address != "" {
						c.Street = append(c.Street, address)
					}
				} else {
					c.Street = append(c.Street, line)
				}
			case "admin":
				c := parsedWhois.Contacts.Admin
				if c.Name == "" {
					c.Name = line
				} else if strings.HasPrefix(line, "Address:") {
					// Extract address content after "Address:"
					address := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
					if address != "" {
						c.Street = append(c.Street, address)
					}
				} else {
					c.Street = append(c.Street, line)
				}
			case "tech":
				c := parsedWhois.Contacts.Tech
				if c.Name == "" {
					c.Name = line
				} else if strings.HasPrefix(line, "Address:") {
					// Extract address content after "Address:"
					address := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
					if address != "" {
						c.Street = append(c.Street, address)
					}
				} else {
					c.Street = append(c.Street, line)
				}
			}
		}
	}

	return parsedWhois, nil
}
