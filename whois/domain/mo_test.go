package domain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMOTLDParser_Parse_Registered(t *testing.T) {
	parser := NewMOTLDParser()
	dir := "testdata/mo"
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to read testdata/mo: %v", err)
	}
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "case") || file.IsDir() {
			continue
		}
		if file.Name() == "case1.txt" || file.Name() == "case2.txt" || file.Name() == "case3.txt" || file.Name() == "case7.txt" || file.Name() == "case8.txt" || file.Name() == "case9.txt" || file.Name() == "case10.txt" || file.Name() == "case11.txt" {
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
		if len(parsed.NameServers) == 0 {
			t.Errorf("%s: expected nameservers, got none", path)
		}
	}
}

func TestMOTLDParser_Parse_Unregistered(t *testing.T) {
	parser := NewMOTLDParser()
	unregFiles := []string{"case1.txt", "case2.txt", "case3.txt", "case7.txt", "case8.txt", "case9.txt", "case10.txt", "case11.txt"}
	for _, fname := range unregFiles {
		path := filepath.Join("testdata/mo", fname)
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
