package domain

import (
	"testing"
)

func TestVEParser(t *testing.T) {
	parser := NewVETLDParser()
	if parser.GetName() != "ve" {
		t.Errorf("Expected parser name to be 've', got '%s'", parser.GetName())
	}

	// Test registered domain
	whoisText := `
%  Servidor whois del Centro de Información de Red de Venezuela (NIC.VE)
%  Este servidor contiene información autoritativa exclusivamente de dominios .ve
% 
% Whoisd Server Version: 3.12.1
% Timestamp: Wed Jun 18 20:52:50 2025

domain:       nic.ve
registrant:   CON000031823
admin-c:      CON000031823
nsset:        DNS000114779
keyset:       KEY000000001
registrar:    NIC-VE
registered:   08.08.2019 18:04:00
changed:      03.06.2024 14:34:08
expire:       31.12.2034

contact:      CON000031823
address:      Definir Dirección
address:      Caracas
address:      1012
address:      VE
registrar:    NIC-VE
created:      04.08.2019 17:18:51

nsset:        DNS000114779
nserver:      ns3.nic.ve (190.9.129.56)
nserver:      ns4.nic.ve (190.202.128.43)
nserver:      ns5.nic.ve (45.175.22.88, 2801:18:8800:3:18ba:beff:fe61:d08b)
nserver:      ns6.nic.ve (45.175.22.4, 2801:18:8800:1::4)
tech-c:       CON000031823
registrar:    NIC-VE
created:      08.08.2019 18:03:59
changed:      25.09.2019 08:52:41
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "nic.ve" {
		t.Errorf("Expected domain name 'nic.ve', got '%s'", parsed.DomainName)
	}

	if parsed.Registrar == nil || parsed.Registrar.Name != "NIC-VE" {
		t.Errorf("Expected registrar name 'NIC-VE', got '%v'", parsed.Registrar)
	}

	expectedNS := []string{"ns3.nic.ve", "ns4.nic.ve", "ns5.nic.ve", "ns6.nic.ve"}
	if len(parsed.NameServers) != len(expectedNS) {
		t.Errorf("Expected %d nameservers, got %d", len(expectedNS), len(parsed.NameServers))
	}

	// Check that all expected nameservers are present
	for _, expectedNS := range expectedNS {
		found := false
		for _, actualNS := range parsed.NameServers {
			if actualNS == expectedNS {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected nameserver '%s' not found in %v", expectedNS, parsed.NameServers)
		}
	}

	if parsed.CreatedDateRaw != "08.08.2019 18:04:00" {
		t.Errorf("Expected created date '08.08.2019 18:04:00', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.UpdatedDateRaw != "03.06.2024 14:34:08" {
		t.Errorf("Expected updated date '03.06.2024 14:34:08', got '%s'", parsed.UpdatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "31.12.2034" {
		t.Errorf("Expected expiry date '31.12.2034', got '%s'", parsed.ExpiredDateRaw)
	}
}

func TestVEParserUnregistered(t *testing.T) {
	parser := NewVETLDParser()

	// Test unregistered domain
	whoisText := `
%  Servidor whois del Centro de Información de Red de Venezuela (NIC.VE)
%  Este servidor contiene información autoritativa exclusivamente de dominios .ve
% 
% Whoisd Server Version: 3.12.1

%ERROR:101: no entries found
% 
% No entries found.
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "" {
		t.Errorf("Expected empty domain name for unregistered domain, got '%s'", parsed.DomainName)
	}

	if parsed.CreatedDateRaw != "" {
		t.Errorf("Expected empty creation date for unregistered domain, got '%s'", parsed.CreatedDateRaw)
	}

	if len(parsed.Statuses) != 0 {
		t.Errorf("Expected no statuses for unregistered domain, got %v", parsed.Statuses)
	}

	if parsed.Registrar != nil && parsed.Registrar.Name != "" {
		t.Errorf("Expected empty registrar for unregistered domain, got '%s'", parsed.Registrar.Name)
	}

	if len(parsed.NameServers) != 0 {
		t.Errorf("Expected no nameservers for unregistered domain, got %v", parsed.NameServers)
	}
}

func TestVEParserWithStatus(t *testing.T) {
	parser := NewVETLDParser()

	// Test domain with status
	whoisText := `
%  Servidor whois del Centro de Información de Red de Venezuela (NIC.VE)
%  Este servidor contiene información autoritativa exclusivamente de dominios .ve
% 
% Whoisd Server Version: 3.12.1
% Timestamp: Wed Jun 18 20:52:54 2025

domain:       dns.ve
registrant:   CON000031823
admin-c:      CON000031823
registrar:    NIC-VE
status:       The domain isn't generated in the zone
registered:   20.03.2025 16:57:57
expire:       20.03.2034

contact:      CON000031823
address:      Definir Dirección
address:      Caracas
address:      1012
address:      VE
registrar:    NIC-VE
created:      04.08.2019 17:18:51
`

	parsed, err := parser.GetParsedWhois(whoisText)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if parsed.DomainName != "dns.ve" {
		t.Errorf("Expected domain name 'dns.ve', got '%s'", parsed.DomainName)
	}

	if len(parsed.Statuses) != 1 || parsed.Statuses[0] != "The domain isn't generated in the zone" {
		t.Errorf("Expected status 'The domain isn't generated in the zone', got %v", parsed.Statuses)
	}

	if parsed.CreatedDateRaw != "20.03.2025 16:57:57" {
		t.Errorf("Expected created date '20.03.2025 16:57:57', got '%s'", parsed.CreatedDateRaw)
	}

	if parsed.ExpiredDateRaw != "20.03.2034" {
		t.Errorf("Expected expiry date '20.03.2034', got '%s'", parsed.ExpiredDateRaw)
	}
}
