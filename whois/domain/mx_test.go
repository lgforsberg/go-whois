package domain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMXTLDParser_Parse_Registered(t *testing.T) {
	parser := NewMXTLDParser()
	dir := "testdata/mx"
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to read testdata/mx: %v", err)
	}

	unregisteredFiles := map[string]bool{
		"case4.txt": true, "case7.txt": true, "case8.txt": true,
		"case9.txt": true, "case10.txt": true, "case11.txt": true,
	}

	for _, file := range files {
		if !isValidTestFile(file) || unregisteredFiles[file.Name()] {
			continue
		}

		path := filepath.Join(dir, file.Name())
		parsed, err := parseMXTestFile(parser, path)
		if err != nil {
			t.Errorf("Error processing %s: %v", path, err)
			continue
		}

		assertMXRegisteredDomain(t, parsed, path)
	}
}

func TestMXTLDParser_Parse_Unregistered(t *testing.T) {
	parser := NewMXTLDParser()
	unregFiles := []string{"case4.txt", "case7.txt", "case8.txt", "case9.txt", "case10.txt", "case11.txt"}

	for _, fname := range unregFiles {
		path := filepath.Join("testdata/mx", fname)
		parsed, err := parseMXTestFile(parser, path)
		if err != nil {
			t.Errorf("Error processing %s: %v", path, err)
			continue
		}

		assertMXUnregisteredDomain(t, parsed, path)
	}
}

func isValidTestFile(file os.DirEntry) bool {
	return strings.HasPrefix(file.Name(), "case") && !file.IsDir()
}

func parseMXTestFile(parser *MXTLDParser, path string) (*ParsedWhois, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parsed, err := parser.GetParsedWhois(string(data))
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func assertMXRegisteredDomain(t *testing.T, parsed *ParsedWhois, path string) {
	if parsed.DomainName == "" {
		t.Errorf("%s: expected domain name, got empty", path)
	}
	if parsed.CreatedDateRaw == "" {
		t.Errorf("%s: expected created date, got empty", path)
	}
	if parsed.ExpiredDateRaw == "" {
		t.Errorf("%s: expected expired date, got empty", path)
	}
	if parsed.Registrar == nil || parsed.Registrar.Name == "" {
		t.Errorf("%s: expected registrar name, got empty", path)
	}
	if len(parsed.NameServers) == 0 {
		t.Errorf("%s: expected nameservers, got none", path)
	}
}

func assertMXUnregisteredDomain(t *testing.T, parsed *ParsedWhois, path string) {
	expectedStatuses := []string{"not_found"}
	if len(parsed.Statuses) != len(expectedStatuses) {
		t.Errorf("%s: expected %d statuses, got %d: %v", path, len(expectedStatuses), len(parsed.Statuses), parsed.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsed.Statuses[i] != expected {
			t.Errorf("%s: expected status %d to be '%s', got '%s'", path, i, expected, parsed.Statuses[i])
		}
	}
}
