package domain

import (
	"testing"
)

func TestJPTLDParser(t *testing.T) {
	parser := NewJPTLDParser()
	if parser.GetName() != "jp" {
		t.Errorf("Expected parser name to be 'jp', got '%s'", parser.GetName())
	}

	// Test registered domain (case1)
	rawtext := `[ JPRS database provides information on network administration. Its use is    ]
[ restricted to network administration purposes. For further information,     ]
[ use 'whois -h whois.jprs.jp help'. To suppress Japanese output, add'/e'     ]
[ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]
Domain Information: [ドメイン情報]
[Domain Name]                   GOOGLE.JP

[登録者名]                      Google LLC
[Registrant]                    Google LLC

[Name Server]                   ns1.google.com
[Name Server]                   ns2.google.com
[Name Server]                   ns3.google.com
[Name Server]                   ns4.google.com
[Signing Key]                   

[登録年月日]                    2005/05/30
[有効期限]                      2026/05/31
[状態]                          Active
[ロック状態]                    DomainTransferLocked
[ロック状態]                    AgentChangeLocked
[最終更新]                      2025/06/01 01:05:04 (JST)

Contact Information: [公開連絡窓口]
[名前]                          Google LLC
[Name]                          Google LLC
[Email]                         dns-admin@google.com
[Web Page]                       
[郵便番号]                      94043
[住所]                          Mountain View
                                1600 Amphitheatre Parkway
                                CA
[Postal Address]                Mountain View
                                1600 Amphitheatre Parkway
                                CA
[電話番号]                      16502530000
[FAX番号]                       16502530001`

	parsedWhois, err := parser.GetParsedWhois(rawtext)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	assertJPRegisteredDomain(t, parsedWhois, "GOOGLE.JP", []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}, "2005/05/30", "2026/05/31", "2025/06/01 01:05:04 (JST)")

	// Test unregistered domain (case8)
	rawtextFree := `[ JPRS database provides information on network administration. Its use is    ]
[ restricted to network administration purposes. For further information,     ]
[ use 'whois -h whois.jprs.jp help'. To suppress Japanese output, add'/e'     ]
[ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]
No match!!

JPRS WHOISは、JPRSが管理している以下のドメイン名に関する情報を確認でき
るサービスです。
    ・登録されているJPドメイン名
    ・JPRSを管理レジストラとするgTLD等ドメイン名
詳しくは https://jprs.jp/about/dom-search/jprs-whois/ を参照してください。

参考: IPアドレスのWHOISサーバ
   ・JPNIC WHOIS(whois.nic.ad.jp)
   ・APNIC WHOIS(whois.apnic.net)
   ・ARIN WHOIS(whois.arin.net)
   ・RIPE WHOIS(whois.ripe.net)
   ・LACNIC WHOIS(whois.lacnic.net)
   ・AfriNIC WHOIS(whois.afrinic.net)`

	parsedWhoisFree, err := parser.GetParsedWhois(rawtextFree)
	if err != nil {
		t.Errorf("Expected no error for free domain, got %v", err)
	}

	assertJPUnregisteredDomain(t, parsedWhoisFree)
}

func assertJPRegisteredDomain(t *testing.T, parsedWhois *ParsedWhois, expectedDomain string, expectedNS []string, expectedCreated, expectedExpired, expectedUpdated string) {
	if parsedWhois.DomainName != expectedDomain {
		t.Errorf("Expected domain name to be '%s', got '%s'", expectedDomain, parsedWhois.DomainName)
	}

	assertStringSliceEqualJP(t, parsedWhois.NameServers, expectedNS, "name server")

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "Active" {
		t.Errorf("Expected status to be 'Active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != expectedCreated {
		t.Errorf("Expected created date raw to be '%s', got '%s'", expectedCreated, parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != expectedExpired {
		t.Errorf("Expected expired date raw to be '%s', got '%s'", expectedExpired, parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != expectedUpdated {
		t.Errorf("Expected updated date raw to be '%s', got '%s'", expectedUpdated, parsedWhois.UpdatedDateRaw)
	}
}

func assertJPUnregisteredDomain(t *testing.T, parsedWhois *ParsedWhois) {
	expectedStatuses := []string{"not_found"}
	if len(parsedWhois.Statuses) != len(expectedStatuses) {
		t.Errorf("Expected %d statuses, got %d: %v", len(expectedStatuses), len(parsedWhois.Statuses), parsedWhois.Statuses)
		return
	}

	for i, expected := range expectedStatuses {
		if parsedWhois.Statuses[i] != expected {
			t.Errorf("Expected status %d to be '%s', got '%s'", i, expected, parsedWhois.Statuses[i])
		}
	}

	if len(parsedWhois.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhois.NameServers))
	}

	if parsedWhois.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhois.UpdatedDateRaw)
	}
}

func assertStringSliceEqualJP(t *testing.T, actual, expected []string, label string) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %d %s(s), got %d", len(expected), label, len(actual))
		return
	}
	for i, v := range expected {
		if i < len(actual) && actual[i] != v {
			t.Errorf("Expected %s %d to be '%s', got '%s'", label, i, v, actual[i])
		}
	}
}
