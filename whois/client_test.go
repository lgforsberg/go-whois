package whois

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lgforsberg/go-whois/whois/domain"
)

func TestQuery(t *testing.T) {
	// mock whois server
	whoisServer, err := StartMockWhoisServer(":0")
	require.Nil(t, err)
	defer whoisServer.Close()
	whoisServerAddr := whoisServer.Addr().String()
	whoisServerHost := whoisServerAddr[:strings.LastIndex(whoisServerAddr, ":")]
	testWhoisPort, err := strconv.Atoi(whoisServerAddr[strings.LastIndex(whoisServerAddr, ":")+1:])
	require.Nil(t, err)
	testServerMap := DomainWhoisServerMap{}
	client, err := NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
	require.Nil(t, err)
	exp, err := client.Parse(TestDomain, NewRaw(TestDomainWhoisRawText, whoisServerHost))
	require.Nil(t, err)

	// Apply availability determination to expected result for consistency with Query behavior
	// github.io is a registered domain, so it should be not available
	client.determineAvailability(exp, nil)

	t.Run("QueryDomain", func(t *testing.T) {
		testServerMap = DomainWhoisServerMap{"io": []WhoisServer{{Host: whoisServerHost}}}
		client, err = NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		w, err := client.Query(context.Background(), TestDomain)
		assert.Nil(t, err)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryDomainSpecificWhoisServer", func(t *testing.T) {
		testServerMap = DomainWhoisServerMap{}
		client, err = NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		w, err := client.Query(context.Background(), TestDomain, whoisServerHost)
		assert.Nil(t, err)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryDomainChan", func(t *testing.T) {
		testServerMap = DomainWhoisServerMap{"io": []WhoisServer{{Host: whoisServerHost}}}
		client, err = NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		status := &Status{PublicSuffixs: []string{"github.io"}}
		finishChan := client.QueryPublicSuffixsChan(status)
		w := <-finishChan
		assert.Nil(t, status.Err)
		assert.Equal(t, RespTypeFound, status.RespType)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryDomainChanSpecificWhoisServer", func(t *testing.T) {
		testServerMap = DomainWhoisServerMap{}
		client, err = NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		status := &Status{PublicSuffixs: []string{"github.io"}, WhoisServer: whoisServerHost}
		finishChan := client.QueryPublicSuffixsChan(status)
		w := <-finishChan
		assert.Nil(t, status.Err)
		assert.Equal(t, RespTypeFound, status.RespType)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryWhoisContainsNotFoundText", func(t *testing.T) {
		testServerMap = DomainWhoisServerMap{"app": []WhoisServer{{Host: whoisServerHost}}}
		client, err = NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		w, err := client.Query(context.Background(), TestNotFoundDomain)
		assert.ErrorIs(t, ErrDomainIPNotFound, err)
		assert.Equal(t, "No match for "+TestNotFoundDomain, w.RawText)
	})
}

func TestQueryError(t *testing.T) {
	testServerMap := DomainWhoisServerMap{}
	client, err := NewClient(WithTimeout(3*time.Second), WithServerMap(testServerMap))
	require.Nil(t, err)

	t.Run("PublicSuffixErr", func(t *testing.T) {
		_, err := client.Query(context.Background(), "com")
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "publicsuffix")
	})

	t.Run("UnknownWhoisServer", func(t *testing.T) {
		w, err := client.Query(context.Background(), "aaa.aaa")
		assert.Nil(t, w)
		assert.Contains(t, err.Error(), "unknown whois server")
	})

	t.Run("QueryWhoisServerConnFailed", func(t *testing.T) {
		serverMap := DomainWhoisServerMap{"aaa": []WhoisServer{{Host: "localhost"}}}
		client, err := NewClient(WithTimeout(3*time.Second), WithServerMap(serverMap), WithIANA(":12345"))
		require.Nil(t, err)
		_, err = client.Query(context.Background(), "aaa.aaa")
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "connection refused")
	})

	t.Run("QueryWhoisServerNotResp", func(t *testing.T) {
		whoisServer, err := StartMockWhoisServer(":0", func(conn net.Conn) {
			if conn != nil {
				time.Sleep(2 * time.Second)
				conn.Close()
			}
		})
		assert.Nil(t, err)
		defer whoisServer.Close()

		whoisServerAddr := whoisServer.Addr().String()
		whoisServerHost := whoisServerAddr[:strings.LastIndex(whoisServerAddr, ":")]
		testWhoisPort, err := strconv.Atoi(whoisServerAddr[strings.LastIndex(whoisServerAddr, ":")+1:])
		require.Nil(t, err)

		serverMap := DomainWhoisServerMap{"aaa": []WhoisServer{{Host: whoisServerHost}}}
		client, err := NewClient(WithTimeout(1*time.Second), WithServerMap(serverMap))
		require.Nil(t, err)
		client.whoisPort = testWhoisPort
		w, err := client.Query(context.Background(), "aaa.aaa")
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrTimeout)
	})

	t.Run("QueryWhoisServerConnFailedChan", func(t *testing.T) {
		serverMap := DomainWhoisServerMap{"aaa": []WhoisServer{{Host: "localhost"}}}
		client, err := NewClient(WithTimeout(3*time.Second), WithServerMap(serverMap), WithIANA(":12345"))
		require.Nil(t, err)
		status := &Status{PublicSuffixs: []string{"aaa.aaa"}}
		finishChan := client.QueryPublicSuffixsChan(status)
		<-finishChan
		assert.Equal(t, RespTypeError, status.RespType)
		assert.NotNil(t, status.Err)
		assert.Contains(t, status.Err.Error(), "connection refused")
	})
}

func TestQueryIP(t *testing.T) {
	// mock whois server
	whoisServer, err := StartMockWhoisServer(":0")
	require.Nil(t, err)
	defer whoisServer.Close()
	whoisServerAddr := whoisServer.Addr().String()
	whoisServerHost := whoisServerAddr[:strings.LastIndex(whoisServerAddr, ":")]
	testWhoisPort, err := strconv.Atoi(whoisServerAddr[strings.LastIndex(whoisServerAddr, ":")+1:])
	require.Nil(t, err)

	// mock ARIN server
	arinServer, err := StartMockWhoisServer(":0", func(conn net.Conn) {
		if conn != nil {
			var bs = make([]byte, 1024)
			n, _ := conn.Read(bs)
			switch strings.TrimSpace(string(bs[:n])) {
			case "n " + TestIP, "n " + TestNotFoundIP:
				conn.Write([]byte("OrgId: test\n"))
			}
			conn.Close()
		}
	})
	require.Nil(t, err)
	defer arinServer.Close()
	arinServerAddr := arinServer.Addr().String()
	testServerMap := DomainWhoisServerMap{}
	client, err := NewClient(
		WithTimeout(3*time.Second),
		WithARIN(arinServerAddr),
		WithTestingWhoisPort(testWhoisPort),
		WithServerMap(testServerMap),
	)
	require.Nil(t, err)
	client.arinMap["test"] = whoisServerHost
	exp, err := client.ParseIP(TestIP, NewRaw(TestIPWhoisRawText, whoisServerHost))
	require.Nil(t, err)

	t.Run("QueryIP", func(t *testing.T) {
		w, err := client.QueryIP(context.Background(), TestIP)
		assert.Nil(t, err)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryIPSpecificWhoisServer", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithARIN(arinServerAddr),
			WithTestingWhoisPort(testWhoisPort),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		w, err := client.QueryIP(context.Background(), TestIP, whoisServerHost)
		assert.Nil(t, err)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryIPChan", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithARIN(arinServerAddr),
			WithTestingWhoisPort(testWhoisPort),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		client.arinMap["test"] = whoisServerHost
		status := &Status{DomainOrIP: TestIP}
		finishChan := client.QueryIPChan(status)
		w := <-finishChan
		assert.Nil(t, status.Err)
		assert.Equal(t, RespTypeFound, status.RespType)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryIPChanSpecificWhoisServer", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithTestingWhoisPort(testWhoisPort),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		status := &Status{DomainOrIP: TestIP, WhoisServer: whoisServerHost}
		finishChan := client.QueryIPChan(status)
		w := <-finishChan
		assert.Nil(t, status.Err)
		assert.Equal(t, RespTypeFound, status.RespType)
		assert.Empty(t, cmp.Diff(exp, w))
	})

	t.Run("QueryIPWhoisContainsNotFoundText", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithARIN(arinServerAddr),
			WithTestingWhoisPort(testWhoisPort),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		client.arinMap["test"] = whoisServerHost
		w, err := client.QueryIP(context.Background(), TestNotFoundIP)
		assert.ErrorIs(t, ErrDomainIPNotFound, err)
		assert.Equal(t, "No match found for "+TestNotFoundIP, w.RawText)
	})
}

func TestQueryIPError(t *testing.T) {
	// mock whois server
	whoisServer, err := StartMockWhoisServer(":0")
	require.Nil(t, err)
	defer whoisServer.Close()
	whoisServerAddr := whoisServer.Addr().String()
	whoisServerHost := whoisServerAddr[:strings.LastIndex(whoisServerAddr, ":")]
	testWhoisPort, err := strconv.Atoi(whoisServerAddr[strings.LastIndex(whoisServerAddr, ":")+1:])
	require.Nil(t, err)

	// mock ARIN server
	testIPwithoutOrgID := "30.42.41.64"
	testIPnotResp := "40.123.46.74"
	arinServer, err := StartMockWhoisServer(":0", func(conn net.Conn) {
		if conn != nil {
			var bs = make([]byte, 1024)
			n, _ := conn.Read(bs)
			switch strings.TrimSpace(string(bs[:n])) {
			case "n " + testIPwithoutOrgID:
				conn.Write([]byte("OrgName: test\n"))
			case "n " + testIPnotResp:
				time.Sleep(3 * time.Second)
				conn.Write([]byte("OrgId: test\n"))
			}
			conn.Close()
		}
	})
	require.Nil(t, err)
	defer arinServer.Close()
	arinServerAddr := arinServer.Addr().String()
	arinServerHost := arinServerAddr[:strings.LastIndex(arinServerAddr, ":")]
	testServerMap := DomainWhoisServerMap{}
	client, err := NewClient(
		WithTimeout(3*time.Second),
		WithARIN(arinServerAddr),
		WithTestingWhoisPort(testWhoisPort),
		WithServerMap(testServerMap),
	)
	require.Nil(t, err)
	client.arinMap["test"] = whoisServerHost

	t.Run("NoOrgIdReturnARINresult", func(t *testing.T) {
		w, err := client.QueryIP(context.Background(), testIPwithoutOrgID)
		assert.Nil(t, err)
		assert.Equal(t, "OrgName: test\n", w.RawText)
	})

	wrongArinServerAddr := arinServerHost + ":12345"
	t.Run("QueryWhoisServerConnFailed", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithARIN(wrongArinServerAddr),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		w, err := client.QueryIP(context.Background(), TestIP)
		assert.Nil(t, w)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "connection refused")
	})

	t.Run("QueryWhoisServerNotResp", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(1*time.Second),
			WithARIN(arinServerAddr),
			WithTestingWhoisPort(testWhoisPort),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		w, err := client.QueryIP(context.Background(), testIPnotResp)
		assert.Nil(t, w)
		assert.ErrorIs(t, err, ErrTimeout)
	})

	t.Run("QueryWhoisServerConnFailedChan", func(t *testing.T) {
		client, err := NewClient(
			WithTimeout(3*time.Second),
			WithARIN(wrongArinServerAddr),
			WithServerMap(testServerMap),
		)
		require.Nil(t, err)
		status := &Status{DomainOrIP: TestIP}
		finishChan := client.QueryIPChan(status)
		<-finishChan
		assert.Equal(t, RespTypeError, status.RespType)
		assert.NotNil(t, status.Err)
		assert.Contains(t, status.Err.Error(), "connection refused")
	})
}

func TestClientDetermineAvailability(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test status-based availability detection (Phase 1 dual status)
	testCases := []struct {
		name          string
		statuses      []string
		expectedAvail bool
		description   string
	}{
		{
			name:          "Dual status - not found",
			statuses:      []string{"not_found"},
			expectedAvail: true,
			description:   "Phase 1 dual status should be available",
		},
		{
			name:          "Legacy free status",
			statuses:      []string{"free"},
			expectedAvail: true,
			description:   "Legacy free status should be available",
		},
		{
			name:          "New not found status",
			statuses:      []string{"not_found"},
			expectedAvail: true,
			description:   "New not_found status should be available",
		},
		{
			name:          "Active domain",
			statuses:      []string{"active"},
			expectedAvail: false,
			description:   "Active domain should not be available",
		},
		{
			name:          "Registered domain",
			statuses:      []string{"registered"},
			expectedAvail: false,
			description:   "Registered domain should not be available",
		},
		{
			name:          "OK status domain",
			statuses:      []string{"ok"},
			expectedAvail: false,
			description:   "OK status domain should not be available",
		},
		{
			name:          "Empty statuses",
			statuses:      []string{},
			expectedAvail: false,
			description:   "Empty statuses should default to not available",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			whois := &domain.Whois{
				ParsedWhois: &domain.ParsedWhois{
					Statuses: tc.statuses,
				},
				RawText: "test rawtext",
			}

			client.determineAvailability(whois, nil)

			if whois.IsAvailable == nil {
				t.Errorf("Expected IsAvailable to be set, got nil")
				return
			}

			if *whois.IsAvailable != tc.expectedAvail {
				t.Errorf("Expected available to be %v, got %v. %s", tc.expectedAvail, *whois.IsAvailable, tc.description)
			}
		})
	}
}

func TestClientDetermineAvailabilityFallback(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test XML pattern fallback
	xmlAvail := true
	whois := &domain.Whois{
		ParsedWhois: &domain.ParsedWhois{
			Statuses: []string{}, // No statuses
		},
		RawText: "some domain text",
	}

	client.determineAvailability(whois, &xmlAvail)

	if whois.IsAvailable == nil || *whois.IsAvailable != true {
		t.Errorf("Expected fallback to XML pattern (available=true), got %v", whois.IsAvailable)
	}

	// Test WhoisNotFound fallback
	whois2 := &domain.Whois{
		ParsedWhois: &domain.ParsedWhois{
			Statuses: []string{}, // No statuses
		},
		RawText: "No match for domain.com", // Should trigger WhoisNotFound
	}

	client.determineAvailability(whois2, nil)

	if whois2.IsAvailable == nil || *whois2.IsAvailable != true {
		t.Errorf("Expected fallback to WhoisNotFound (available=true), got %v", whois2.IsAvailable)
	}

	// Test default case
	whois3 := &domain.Whois{
		ParsedWhois: &domain.ParsedWhois{
			Statuses: []string{}, // No statuses
		},
		RawText: "registered domain text", // No "not found" patterns
	}

	client.determineAvailability(whois3, nil)

	if whois3.IsAvailable == nil || *whois3.IsAvailable != false {
		t.Errorf("Expected default case (available=false), got %v", whois3.IsAvailable)
	}
}
