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

	if parsedWhois.DomainName != "GOOGLE.JP" {
		t.Errorf("Expected domain name to be 'GOOGLE.JP', got '%s'", parsedWhois.DomainName)
	}

	if len(parsedWhois.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(parsedWhois.NameServers))
	}

	expectedNS := []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"}
	for i, ns := range expectedNS {
		if parsedWhois.NameServers[i] != ns {
			t.Errorf("Expected name server %d to be '%s', got '%s'", i, ns, parsedWhois.NameServers[i])
		}
	}

	if len(parsedWhois.Statuses) != 1 || parsedWhois.Statuses[0] != "Active" {
		t.Errorf("Expected status to be 'Active', got %v", parsedWhois.Statuses)
	}

	if parsedWhois.CreatedDateRaw != "2005/05/30" {
		t.Errorf("Expected created date raw to be '2005/05/30', got '%s'", parsedWhois.CreatedDateRaw)
	}

	if parsedWhois.ExpiredDateRaw != "2026/05/31" {
		t.Errorf("Expected expired date raw to be '2026/05/31', got '%s'", parsedWhois.ExpiredDateRaw)
	}

	if parsedWhois.UpdatedDateRaw != "2025/06/01 01:05:04 (JST)" {
		t.Errorf("Expected updated date raw to be '2025/06/01 01:05:04 (JST)', got '%s'", parsedWhois.UpdatedDateRaw)
	}

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

	if len(parsedWhoisFree.Statuses) != 1 || parsedWhoisFree.Statuses[0] != "free" {
		t.Errorf("Expected status to be 'free', got %v", parsedWhoisFree.Statuses)
	}

	// Verify that free domains have no nameservers or dates
	if len(parsedWhoisFree.NameServers) != 0 {
		t.Errorf("Expected no name servers for free domain, got %d", len(parsedWhoisFree.NameServers))
	}

	if parsedWhoisFree.CreatedDateRaw != "" {
		t.Errorf("Expected no created date for free domain, got '%s'", parsedWhoisFree.CreatedDateRaw)
	}

	if parsedWhoisFree.ExpiredDateRaw != "" {
		t.Errorf("Expected no expired date for free domain, got '%s'", parsedWhoisFree.ExpiredDateRaw)
	}

	if parsedWhoisFree.UpdatedDateRaw != "" {
		t.Errorf("Expected no updated date for free domain, got '%s'", parsedWhoisFree.UpdatedDateRaw)
	}
}
