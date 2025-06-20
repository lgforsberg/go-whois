package domain

import (
	"strings"
)

type QATLDParser struct {
	parser IParser
}

func NewQATLDParser() *QATLDParser {
	return &QATLDParser{
		parser: NewParser(),
	}
}

func (q *QATLDParser) GetName() string {
	return "qa"
}

func (q *QATLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")

	// Handle unregistered or restricted domains
	for _, line := range lines {
		if strings.Contains(line, "not Available") || strings.Contains(line, "restricted this term") {
			parsedWhois.Statuses = []string{"free"}
			return parsedWhois, nil
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Domain Name:") {
			parsedWhois.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Last Modified:") {
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(strings.TrimPrefix(line, "Last Modified:"))
		} else if strings.HasPrefix(line, "Registrar Name:") {
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(strings.TrimPrefix(line, "Registrar Name:"))
		} else if strings.HasPrefix(line, "Status:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			if status != "" {
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
		} else if strings.HasPrefix(line, "Name Server:") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "Name Server:"))
			if ns != "" {
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		}
	}

	return parsedWhois, nil
}
