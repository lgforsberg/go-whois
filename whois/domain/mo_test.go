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

	unregisteredFiles := map[string]bool{
		"case1.txt": true, "case2.txt": true, "case3.txt": true,
		"case7.txt": true, "case8.txt": true, "case9.txt": true,
		"case10.txt": true, "case11.txt": true,
	}

	for _, file := range files {
		if !isValidMOTestFile(file) || unregisteredFiles[file.Name()] {
			continue
		}

		path := filepath.Join(dir, file.Name())
		parsed, err := parseMOTestFile(parser, path)
		if err != nil {
			t.Errorf("Error processing %s: %v", path, err)
			continue
		}

		assertMORegisteredDomain(t, parsed, path)
	}
}

func TestMOTLDParser_Parse_Unregistered(t *testing.T) {
	parser := NewMOTLDParser()
	unregFiles := []string{"case1.txt", "case2.txt", "case3.txt", "case7.txt", "case8.txt", "case9.txt", "case10.txt", "case11.txt"}

	for _, fname := range unregFiles {
		path := filepath.Join("testdata/mo", fname)
		parsed, err := parseMOTestFile(parser, path)
		if err != nil {
			t.Errorf("Error processing %s: %v", path, err)
			continue
		}

		assertMOUnregisteredDomain(t, parsed, path)
	}
}

func isValidMOTestFile(file os.DirEntry) bool {
	return strings.HasPrefix(file.Name(), "case") && !file.IsDir()
}

func parseMOTestFile(parser *MOTLDParser, path string) (*ParsedWhois, error) {
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

func assertMORegisteredDomain(t *testing.T, parsed *ParsedWhois, path string) {
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

func assertMOUnregisteredDomain(t *testing.T, parsed *ParsedWhois, path string) {
	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "free" {
		t.Errorf("%s: expected status 'free', got %v", path, parsed.Statuses)
	}
}
