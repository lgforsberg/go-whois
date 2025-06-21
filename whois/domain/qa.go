package domain

import (
	"strings"

	"github.com/lgforsberg/go-whois/whois/utils"
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

		switch {
			case strings.HasPrefix(line, "Domain Name:"):
				parsedWhois.DomainName = utils.ExtractField(line, "Domain Name:")
			case strings.HasPrefix(line, "Last Modified:"):
				parsedWhois.UpdatedDateRaw = utils.ExtractField(line, "Last Modified:")
			case utils.IsRegistrarLine(line, "Registrar Name:"):
				if parsedWhois.Registrar == nil {
					parsedWhois.Registrar = &Registrar{}
				}
				parsedWhois.Registrar.Name = utils.ExtractField(line, "Registrar Name:")
			case strings.HasPrefix(line, "Status:"):
				status := utils.ExtractField(line, "Status:")
				if status != "" {
					parsedWhois.Statuses = append(parsedWhois.Statuses, status)
				}
			case utils.HandleNameserverField(line, "Name Server:", &parsedWhois.NameServers):
				// handled by utility
		}
	}

	return parsedWhois, nil
}
