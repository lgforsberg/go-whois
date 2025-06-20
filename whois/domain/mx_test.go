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
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "case") || file.IsDir() {
			continue
		}
		if file.Name() == "case4.txt" || file.Name() == "case7.txt" || file.Name() == "case8.txt" || file.Name() == "case9.txt" || file.Name() == "case10.txt" || file.Name() == "case11.txt" {
			// These are unregistered cases
			continue
		}
		path := filepath.Join(dir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", path, err)
			continue
		}
		parsed, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Errorf("Error parsing %s: %v", path, err)
			continue
		}
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
}

func TestMXTLDParser_Parse_Unregistered(t *testing.T) {
	parser := NewMXTLDParser()
	unregFiles := []string{"case4.txt", "case7.txt", "case8.txt", "case9.txt", "case10.txt", "case11.txt"}
	for _, fname := range unregFiles {
		path := filepath.Join("testdata/mx", fname)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", path, err)
			continue
		}
		parsed, err := parser.GetParsedWhois(string(data))
		if err != nil {
			t.Errorf("Error parsing %s: %v", path, err)
			continue
		}
		if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "free" {
			t.Errorf("%s: expected status 'free', got %v", path, parsed.Statuses)
		}
	}
}
