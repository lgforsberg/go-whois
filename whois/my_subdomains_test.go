package whois

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMalaysiaSubdomains verifies that ALL .my subdomains use the new Tucows server
func TestMalaysiaSubdomains(t *testing.T) {
	serverMap, err := NewDomainWhoisServerMap("../cmd/whois/whois-server-list.xml")
	require.NoError(t, err, "Should load whois server list")

	// All .my TLDs and subdomains should use the new Tucows server
	malaysiaDomains := []string{
		"my",           // Base TLD
		"com.my",       // Commercial
		"edu.my",       // Education
		"gov.my",       // Government
		"net.my",       // Network
		"org.my",       // Organization
		"blogspot.my",  // Blogspot
		"mil.my",       // Military
		"name.my",      // Name
	}

	expectedServer := "whois.mynic.my"

	for _, domain := range malaysiaDomains {
		t.Run(domain, func(t *testing.T) {
			servers := serverMap.GetWhoisServer(domain)
			require.NotEmpty(t, servers, "Should find whois server for .%s", domain)
			assert.Equal(t, expectedServer, servers[0].Host,
				".%s should use new Tucows server (not old whois.mynic.net.my)", domain)
		})
	}
}

// TestMalaysiaOldServerGone verifies the old server is not used anywhere
func TestMalaysiaOldServerGone(t *testing.T) {
	serverMap, err := NewDomainWhoisServerMap("../cmd/whois/whois-server-list.xml")
	require.NoError(t, err)

	oldDeadServer := "whois.mynic.net.my"
	malaysiaDomains := []string{"my", "com.my", "edu.my", "gov.my", "net.my", "org.my"}

	for _, domain := range malaysiaDomains {
		servers := serverMap.GetWhoisServer(domain)
		if len(servers) > 0 {
			assert.NotEqual(t, oldDeadServer, servers[0].Host,
				".%s should NOT use dead server %s", domain, oldDeadServer)
		}
	}
}

// TestMalaysiaRealExample tests the specific case from the user's error
func TestMalaysiaRealExample(t *testing.T) {
	serverMap, err := NewDomainWhoisServerMap("../cmd/whois/whois-server-list.xml")
	require.NoError(t, err)

	// The actual domain that failed: ampcell.com.my
	servers := serverMap.GetWhoisServer("com.my")
	require.NotEmpty(t, servers, "Should find server for com.my")

	assert.Equal(t, "whois.mynic.my", servers[0].Host,
		"ampcell.com.my should resolve to new Tucows server")

	t.Log("✅ ampcell.com.my will now use:", servers[0].Host)
	t.Log("❌ Old dead server was: whois.mynic.net.my")
}

// TestMalaysiaVsArgentinaPattern verifies Malaysia follows the same pattern as Argentina
func TestMalaysiaVsArgentinaPattern(t *testing.T) {
	serverMap, err := NewDomainWhoisServerMap("../cmd/whois/whois-server-list.xml")
	require.NoError(t, err)

	// Argentina pattern (existing)
	arServers := serverMap.GetWhoisServer("com.ar")
	require.NotEmpty(t, arServers)
	assert.Equal(t, "whois.nic.ar", arServers[0].Host, "Argentina subdomains use whois.nic.ar")

	// Malaysia pattern (new - should follow same approach)
	myServers := serverMap.GetWhoisServer("com.my")
	require.NotEmpty(t, myServers)
	assert.Equal(t, "whois.mynic.my", myServers[0].Host, "Malaysia subdomains use whois.mynic.my")

	t.Log("✅ Malaysia overrides follow same pattern as Argentina")
}

