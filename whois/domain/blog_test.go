package domain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlogTLDParser(t *testing.T) {
	// .blog uses standard gTLD format (CIRA backend), so default parser should work
	parser := NewTLDDomainParser("whois.nic.blog")
	require.NotNil(t, parser)

	t.Run("RegisteredDomain", func(t *testing.T) {
		rawtext, err := os.ReadFile(filepath.Join("testdata", "blog", "case1.txt"))
		require.NoError(t, err)

		parsed, err := parser.GetParsedWhois(string(rawtext))
		require.NoError(t, err)

		// Basic domain info
		assert.Equal(t, "official-trustbadges.blog", parsed.DomainName)

		// Dates
		assert.Equal(t, "2026-01-14T02:21:05+00:00", parsed.CreatedDate)
		assert.Equal(t, "2026-01-14T02:21:05+00:00", parsed.UpdatedDate)
		assert.Equal(t, "2027-01-14T02:21:05+00:00", parsed.ExpiredDate)

		// Registrar
		require.NotNil(t, parsed.Registrar)
		assert.Equal(t, "Ultahost, Inc.", parsed.Registrar.Name)
		assert.Equal(t, "4331", parsed.Registrar.IanaID)

		// Statuses - should include EPP statuses that indicate registration
		assert.Contains(t, parsed.Statuses, "addPeriod")
		assert.Contains(t, parsed.Statuses, "serverTransferProhibited")
		// Should NOT have "not_found" status for registered domain
		assert.NotContains(t, parsed.Statuses, "not_found")

		// Name servers
		assert.Contains(t, parsed.NameServers, "journey.ns.cloudflare.com")
		assert.Contains(t, parsed.NameServers, "lamar.ns.cloudflare.com")

		// DNSSEC
		assert.Equal(t, "unsigned", parsed.Dnssec)
	})

	t.Run("NotFoundDomain", func(t *testing.T) {
		rawtext, err := os.ReadFile(filepath.Join("testdata", "blog", "case_notfound.txt"))
		require.NoError(t, err)

		parsed, err := parser.GetParsedWhois(string(rawtext))
		require.NoError(t, err)

		// Should have "not_found" status
		assert.Contains(t, parsed.Statuses, "not_found")

		// Should NOT have registration data
		assert.Empty(t, parsed.CreatedDate)
		assert.Empty(t, parsed.ExpiredDate)
		assert.Nil(t, parsed.Registrar)
	})
}

// TestBlogAvailabilityFalsePositive tests the specific bug where registered .blog
// domains were incorrectly flagged as available due to the word "available"
// appearing in the CIRA legal notice footer.
func TestBlogAvailabilityFalsePositive(t *testing.T) {
	// The word "available" appears in the legal notice of ALL .blog responses:
	// "% Notice, available at https://www.cira.ca/..."
	// This should NOT trigger a false positive for registered domains

	rawtext, err := os.ReadFile(filepath.Join("testdata", "blog", "case1.txt"))
	require.NoError(t, err)

	parser := NewTLDDomainParser("whois.nic.blog")
	parsed, err := parser.GetParsedWhois(string(rawtext))
	require.NoError(t, err)

	// Verify we have registration data that proves this is a registered domain
	assert.NotEmpty(t, parsed.CreatedDate, "Registered domain should have CreatedDate")
	assert.NotEmpty(t, parsed.ExpiredDate, "Registered domain should have ExpiredDate")
	assert.NotNil(t, parsed.Registrar, "Registered domain should have Registrar")
	assert.NotEmpty(t, parsed.Registrar.Name, "Registered domain should have Registrar name")

	// EPP statuses indicate registration
	hasRegisteredStatus := false
	for _, status := range parsed.Statuses {
		switch status {
		case "addPeriod", "serverTransferProhibited", "active", "ok":
			hasRegisteredStatus = true
		}
	}
	assert.True(t, hasRegisteredStatus, "Registered domain should have EPP status indicating registration")
}
