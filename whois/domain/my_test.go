package domain

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMYTLDParser_RegisteredDomain tests parsing of a registered .my domain
// Note: .my TLD uses the default parser after migrating to Tucows Registry Backend
func TestMYTLDParser_RegisteredDomain(t *testing.T) {
	parser := NewTLDDomainParser("whois.mynic.my")
	assert.Equal(t, "default", parser.GetName(), ".my should use default parser after Tucows migration")

	rawtext, err := os.ReadFile("testdata/my/case1.txt")
	require.NoError(t, err)

	parsedWhois, err := parser.GetParsedWhois(string(rawtext))
	require.NoError(t, err)
	require.NotNil(t, parsedWhois)

	// Domain should be found (not have "not_found" status)
	assert.NotContains(t, parsedWhois.Statuses, "not_found", "google.my should be registered")

	// Basic domain information
	assert.Equal(t, "google.my", parsedWhois.DomainName)
	assert.NotEmpty(t, parsedWhois.CreatedDateRaw, "Should have creation date")
	assert.NotEmpty(t, parsedWhois.ExpiredDateRaw, "Should have expiry date")
	assert.NotEmpty(t, parsedWhois.UpdatedDateRaw, "Should have updated date")

	// Registrar information
	assert.NotNil(t, parsedWhois.Registrar)
	assert.NotEmpty(t, parsedWhois.Registrar.Name, "Should have registrar name")
	assert.NotEmpty(t, parsedWhois.Registrar.IanaID, "Should have IANA ID")
	assert.NotEmpty(t, parsedWhois.Registrar.AbuseContactEmail, "Should have abuse email")
	assert.NotEmpty(t, parsedWhois.Registrar.AbuseContactPhone, "Should have abuse phone")

	// Domain status
	assert.NotEmpty(t, parsedWhois.Statuses, "Should have domain status")

	// Nameservers
	assert.NotEmpty(t, parsedWhois.NameServers, "Should have nameservers")
	assert.Contains(t, parsedWhois.NameServers, "ns1.google.com")
	assert.Contains(t, parsedWhois.NameServers, "ns2.google.com")

	// Contacts (should exist even if redacted)
	assert.NotNil(t, parsedWhois.Contacts)
	assert.NotNil(t, parsedWhois.Contacts.Registrant)
	assert.NotNil(t, parsedWhois.Contacts.Admin)
	assert.NotNil(t, parsedWhois.Contacts.Tech)
	assert.NotNil(t, parsedWhois.Contacts.Billing)

	// Verify Tucows-style gTLD format is parsed correctly
	assert.NotEmpty(t, parsedWhois.Contacts.Registrant.Organization, "Should parse Registrant Organization")
	assert.Equal(t, "MY", parsedWhois.Contacts.Registrant.Country, "Should parse country code")
}

// TestMYTLDParser_NotFoundDomain tests parsing of an unregistered .my domain
func TestMYTLDParser_NotFoundDomain(t *testing.T) {
	parser := NewTLDDomainParser("whois.mynic.my")
	assert.Equal(t, "default", parser.GetName())

	rawtext, err := os.ReadFile("testdata/my/case2.txt")
	require.NoError(t, err)

	parsedWhois, err := parser.GetParsedWhois(string(rawtext))
	require.NoError(t, err)
	require.NotNil(t, parsedWhois)

	// Domain should be available (not found)
	assert.Contains(t, parsedWhois.Statuses, "not_found", "notregistereddomaintest12345.my should be available")

	// Should have minimal or no parsed data for unregistered domain
	assert.Empty(t, parsedWhois.DomainName)
	assert.Empty(t, parsedWhois.NameServers)
}

// TestMYTucowsFormat verifies that .my now uses standard Tucows/gTLD format
func TestMYTucowsFormat(t *testing.T) {
	rawtext, err := os.ReadFile("testdata/my/case1.txt")
	require.NoError(t, err)

	content := string(rawtext)

	// Verify Tucows Registry Backend fields are present
	tucowsFields := []string{
		"Registry Domain ID:",
		"Registrar WHOIS Server:",
		"Registrar URL:",
		"Updated Date:",
		"Creation Date:",
		"Registry Expiry Date:",
		"Registrar:",
		"Registrar IANA ID:",
		"Registrar Abuse Contact Email:",
		"Registrar Abuse Contact Phone:",
		"Domain Status:",
		"Registry Registrant ID:",
		"Registrant Name:",
		"Registrant Organization:",
		"Registry Admin ID:",
		"Registry Tech ID:",
		"Registry Billing ID:",
		"Name Server:",
		"DNSSEC:",
	}

	for _, field := range tucowsFields {
		assert.Contains(t, content, field, "Should contain Tucows field: %s", field)
	}

	// Verify it follows standard gTLD format (like .com, .net)
	assert.Contains(t, content, "ICANN", "Should reference ICANN (standard gTLD)")
}

