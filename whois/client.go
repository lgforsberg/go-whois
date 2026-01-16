package whois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	wd "github.com/lgforsberg/go-whois/whois/domain"
	wip "github.com/lgforsberg/go-whois/whois/ip"
	"github.com/lgforsberg/go-whois/whois/utils"
)

const (
	// Values of RespType
	RespTypeFound      = "found"
	RespTypeNotFound   = "not_found"
	RespTypeParseError = "parse_error"
	RespTypeError      = "error"
	RespTypeTimeout    = "timeout"

	// Values of AccType
	TypeDomain = "domain"
	TypeIP     = "ip"

	DefaultWhoisPort       = 43
	DefaultIANAWhoisServer = "whois.iana.org"
	DefaultWriteTimeout    = 10 * time.Second
	DefaultReadTimeout     = 30 * time.Second
	DefaultTimeout         = 5 * time.Second
	// Maximum size for whois responses to prevent memory exhaustion
	MaxWhoisResponseSize = 10 * 1024 * 1024 // 10MB
)

var (
	DefaultIPWhoisServerMap = map[string]string{
		"APNIC":   "whois.apnic.net",
		"ARIN":    "whois.arin.net",
		"RIPE":    "whois.ripe.net",
		"LACNIC":  "whois.lacnic.net",
		"AFRINIC": "whois.afrinic.net",
	}
	DefaultIANA = FmtWhoisServer(DefaultIANAWhoisServer, DefaultWhoisPort)
	DefaultARIN = FmtWhoisServer("whois.arin.net", DefaultWhoisPort)

	// ErrDomainIPNotFound is fixed error message for WHOIS not found
	ErrDomainIPNotFound = errors.New("domain/ip not found")
	// ErrTimeout is fixed error message for timeout quering WHOIS server
	ErrTimeout = errors.New("timeout")
)

// FmtWhoisServer concate host and port to query whois
func FmtWhoisServer(host string, port int) string {
	return host + ":" + strconv.Itoa(port)
}

// Raw records rawtext from whois server
type Raw struct {
	Rawtext string
	Server  string // whois server that response the raw text
	Avail   *bool
}

// Status records response status for query
type Status struct {
	DomainOrIP    string
	PublicSuffixs []string
	WhoisServer   string
	RespType      string
	Err           error
}

// NewStatus creates a new Status instance with the specified whois server.
// Status tracks the progress and results of WHOIS queries.
func NewStatus(ws string) *Status {
	return &Status{WhoisServer: ws}
}

// NewRaw creates a new Raw instance containing raw whois response text.
// If availPtn is provided, it's used to determine domain availability from the raw text.
func NewRaw(rawtext, server string, availPtn ...*regexp.Regexp) *Raw {
	nr := &Raw{Rawtext: rawtext, Server: server}
	if len(availPtn) > 0 {
		isavail := availPtn[0].Match([]byte(rawtext))
		nr.Avail = &isavail
	}
	return nr
}

// Client is used to query whois server to get latest whois information
type Client struct {
	dialer       *net.Dialer
	ianaServAddr string
	arinServAddr string
	arinMap      map[string]string
	whoisMap     DomainWhoisServerMap
	whoisPort    int
	timeout      time.Duration
	wtimeout     time.Duration
	rtimeout     time.Duration
	logger       logrus.FieldLogger
}

// ClientOpts is a function type for configuring Client instances.
// It follows the functional options pattern for flexible client configuration.
type ClientOpts func(*Client) error

// WithTimeout sets the timeout for WHOIS queries.
// It configures read, write, and overall timeouts to the same value.
func WithTimeout(timeout time.Duration) ClientOpts {
	return func(c *Client) error {
		if timeout == 0 {
			return fmt.Errorf("invalid timeout: %v", timeout)
		}
		c.timeout = timeout
		c.rtimeout = timeout
		c.wtimeout = timeout
		return nil
	}
}

// WithServerMap configures the client to use a custom domain-to-whois-server mapping.
// This overrides the default mapping fetched from whois-server-list.xml.
func WithServerMap(serverMap DomainWhoisServerMap) ClientOpts {
	return func(c *Client) error {
		if serverMap == nil {
			return errors.New("invalid server map")
		}
		c.whoisMap = serverMap
		return nil
	}
}

// WithIANA configures the client to use a custom IANA whois server address.
// The address must include both host and port (e.g., "whois.iana.org:43").
func WithIANA(ianaAddr string) ClientOpts {
	return func(c *Client) error {
		if !strings.Contains(ianaAddr, ":") {
			return fmt.Errorf("ianaAddr should contains port, get: %s", ianaAddr)
		}
		c.ianaServAddr = ianaAddr
		return nil
	}
}

// WithARIN configures the client to use a custom ARIN whois server address.
// The address must include both host and port (e.g., "whois.arin.net:43").
func WithARIN(arinAddr string) ClientOpts {
	return func(c *Client) error {
		if !strings.Contains(arinAddr, ":") {
			return fmt.Errorf("arinAddr should contains port, get: %s", arinAddr)
		}
		c.arinServAddr = arinAddr
		return nil
	}
}

// WithTestingWhoisPort is expected to only use in testing since whois port is 43
func WithTestingWhoisPort(port int) ClientOpts {
	return func(c *Client) error {
		c.whoisPort = port
		return nil
	}
}

// WithErrLogger configures the client to use a custom logger for error reporting.
// If not provided, a default logrus logger will be used.
func WithErrLogger(logger logrus.FieldLogger) ClientOpts {
	return func(c *Client) error {
		c.logger = logger
		return nil
	}
}

// NewClient initializes whois client with different options, if whois server map is not given
// it will fetch from http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml
func NewClient(opts ...ClientOpts) (*Client, error) {
	client, err := newClient(opts...)
	if err != nil {
		return nil, err
	}
	if client.whoisMap == nil {
		var err error
		client.whoisMap, err = NewDomainWhoisServerMap(WhoisServerListURL)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

func newClient(opts ...ClientOpts) (*Client, error) {
	c := &Client{
		dialer:       &net.Dialer{},
		ianaServAddr: DefaultIANA,
		arinServAddr: DefaultARIN,
		arinMap:      DefaultIPWhoisServerMap,
		whoisPort:    DefaultWhoisPort,
		wtimeout:     DefaultWriteTimeout,
		rtimeout:     DefaultReadTimeout,
		timeout:      DefaultTimeout,
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if c.logger == nil {
		c.logger = logrus.New()
	}
	return c, nil
}

// determineAvailability determines domain availability with priority-based conflict resolution
// Priority 1: Status-based detection (EPP status codes)
// Priority 2: Registration data validation (CreatedDate, ExpiredDate, Registrar)
// Priority 3: XML pattern fallback
// Priority 4: WhoisNotFound() pattern matching
// Default: Assume registered if no clear indication (safer assumption)
func (c *Client) determineAvailability(w *wd.Whois, xmlAvail *bool) {
	// Priority 1: Status-based detection
	if w.ParsedWhois != nil && len(w.ParsedWhois.Statuses) > 0 {
		for _, status := range w.ParsedWhois.Statuses {
			switch status {
			case "not_found", "free": // Available/unregistered indicators
				available := true
				w.IsAvailable = &available
				return
			case "active", "registered", "ok",
				// EPP client* statuses
				"clientTransferProhibited", "clientDeleteProhibited",
				"clientHold", "clientRenewProhibited", "clientUpdateProhibited",
				// EPP server* statuses
				"serverTransferProhibited", "serverDeleteProhibited",
				"serverHold", "serverRenewProhibited", "serverUpdateProhibited",
				// EPP lifecycle statuses
				"addPeriod", "autoRenewPeriod", "renewPeriod",
				"pendingCreate", "pendingDelete", "pendingRenew",
				"pendingRestore", "pendingTransfer", "pendingUpdate",
				"redemptionPeriod":
				available := false
				w.IsAvailable = &available
				return
			}
		}
	}

	// Priority 2: Registration data validation
	// If we have valid registration data, the domain is definitely registered
	// This prevents false positives from XML patterns matching unrelated text
	if w.ParsedWhois != nil {
		hasRegistrationData := w.ParsedWhois.CreatedDate != "" ||
			w.ParsedWhois.ExpiredDate != "" ||
			(w.ParsedWhois.Registrar != nil && w.ParsedWhois.Registrar.Name != "")
		if hasRegistrationData {
			available := false
			w.IsAvailable = &available
			return
		}
	}

	// Priority 3: XML pattern fallback
	if xmlAvail != nil {
		w.IsAvailable = xmlAvail
		return
	}

	// Priority 4: WhoisNotFound() pattern matching
	if wd.WhoisNotFound(w.RawText) {
		available := true
		w.IsAvailable = &available
		return
	}

	// Default: Assume registered if no clear indication
	available := false
	w.IsAvailable = &available
}

// IsParsePanicErr checks if an error is caused by a panic during WHOIS parsing.
// Parse panics are recovered and converted to errors with "parse error:" prefix.
func IsParsePanicErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), "parse error:")
}

func (c *Client) getText(ctx context.Context, dst, domain string) (string, error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", dst)
	if err != nil {
		return "", fmt.Errorf("failed to dial %s: %w", dst, err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(utils.UTCNow().Add(c.wtimeout)); err != nil {
		return "", fmt.Errorf("set write deadline failed: %w", err)
	}
	if _, err = conn.Write([]byte(domain + "\r\n")); err != nil {
		return "", fmt.Errorf("send to server failed: %w", err)
	}
	if err := conn.SetReadDeadline(utils.UTCNow().Add(c.rtimeout)); err != nil {
		return "", fmt.Errorf("set read deadline failed: %w", err)
	}
	// Use LimitReader to prevent unbounded memory consumption
	limitedReader := io.LimitReader(conn, MaxWhoisResponseSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("read from server failed: %w", err)
	}
	return string(content), nil
}

// QueryRaw query whois server with public suffix
func (c *Client) QueryRaw(ctx context.Context, ps string, whoisServer ...string) (*Raw, error) {
	// Caller specify whois server to query
	if len(whoisServer) > 0 && len(whoisServer[0]) > 0 {
		addr := FmtWhoisServer(whoisServer[0], c.whoisPort)
		resp, err := c.getText(ctx, addr, ps)
		if err != nil {
			return NewRaw("", whoisServer[0]), err
		}
		return NewRaw(resp, whoisServer[0]), nil
	}
	// Not given whois server, search from map and query
	if wss := c.whoisMap.GetWhoisServer(ps); len(wss) > 0 {
		whoisDst := FmtWhoisServer(wss[0].Host, c.whoisPort)
		resp, err := c.getText(ctx, whoisDst, ps)
		if err != nil {
			return NewRaw("", wss[0].Host), err
		}
		if wss[0].AvailPtn != nil {
			return NewRaw(resp, wss[0].Host, wss[0].AvailPtn), nil
		}
		return NewRaw(resp, wss[0].Host), nil
	}
	return nil, errors.New("unknown whois server")
}

// Query get whois information from given whois server or predefined whois server map with domain
func (c *Client) Query(ctx context.Context, domain string, whoisServer ...string) (*wd.Whois, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	domain, err := utils.GetHost(domain)
	if err != nil {
		return nil, err
	}
	pslist, err := utils.GetPublicSuffixs(domain)
	if err != nil && len(pslist) == 0 {
		return nil, err
	}
	return c.QueryPublicSuffixs(ctx, pslist, whoisServer...)
}

// QueryPublicSuffix get whois information from given whois server or predefined whois server map with public suffix
func (c *Client) QueryPublicSuffix(ctx context.Context, ps string, whoisServer ...string) (*wd.Whois, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var wrt *Raw
	var err error
	if wrt, err = c.QueryRaw(ctx, ps, whoisServer...); err != nil {
		return nil, err
	}
	w, err := c.Parse(ps, wrt)
	if err != nil {
		return w, err
	}
	// panic when parsing, w.ParsedWhois = nil
	if IsParsePanicErr(err) {
		return w, err
	}
	return w, nil
}

// QueryPublicSuffixs get whois information from given whois server or predefined whois server map with public suffix list
func (c *Client) QueryPublicSuffixs(ctx context.Context, pslist []string, whoisServer ...string) (*wd.Whois, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var wrt *Raw
	var err error
	var foundPS string
	var isAvail *bool
	for _, ps := range pslist {
		if wrt, err = c.QueryRaw(ctx, ps, whoisServer...); err == nil {
			foundPS = ps
			if wrt.Avail != nil {
				isAvail = wrt.Avail
			}
			break
		}
		if wrt != nil {
			c.logger.WithFields(logrus.Fields{"ps": ps, "whois_server": wrt.Server}).WithError(err).Warn("query WHOIS")
		} else {
			c.logger.WithField("ps", ps).WithError(err).Warn("query WHOIS")
		}
	}

	if err != nil {
		if utils.IsTimeout(err) {
			return nil, ErrTimeout
		}
		return nil, err
	}
	w, err := c.Parse(foundPS, wrt)
	if err != nil {
		return w, err
	}
	c.determineAvailability(w, isAvail)

	// panic when parsing, w.ParsedWhois = nil
	if IsParsePanicErr(err) {
		return w, err
	}
	/* Not return error since availablePattern in whois server list xml file is not always correct... */
	// if w.IsAvailable != nil && *w.IsAvailable {
	// 	return w, ErrDomainIPNotFound
	// }
	if wd.WhoisNotFound(w.RawText) {
		return w, ErrDomainIPNotFound
	}
	return w, nil
}

// Parse get parser based on TLD and use it to parse rawtext. Also check if rawtext contains **not found** keywords
func (c *Client) Parse(ps string, wrt *Raw) (pw *wd.Whois, err error) {
	tld := utils.GetTLD(ps)
	parser := wd.NewTLDDomainParser(wrt.Server)
	defer func() {
		if panicErr := recover(); panicErr != nil {
			c.logger.WithFields(
				logrus.Fields{"ps": ps, "tld": tld, "parser": parser.GetName()},
			).Warnf("panic when parsing raw text: %v", panicErr)
			// still return rawtext and server when parsing failed
			pw = wd.NewWhois(nil, wrt.Rawtext, wrt.Server)
			err = fmt.Errorf("parse error: %s", panicErr.(string))
		}
	}()
	c.logger.WithFields(logrus.Fields{"tld": tld, "parser": parser.GetName()}).Info("parse")

	// Log for panic to avoid crashing server
	parsedWhois, err := parser.GetParsedWhois(wrt.Rawtext)
	if err != nil {
		return nil, err
	}
	pw = wd.NewWhois(parsedWhois, wrt.Rawtext, wrt.Server)
	return pw, nil
}

// QueryPublicSuffixsChan performs query and returns channel for caller to wait for the result
func (c *Client) QueryPublicSuffixsChan(status *Status) chan *wd.Whois {
	result := make(chan *wd.Whois)
	go func() {
		whoisStruct, err := c.QueryPublicSuffixs(context.Background(), status.PublicSuffixs, status.WhoisServer)
		if err != nil {
			status.Err = err
			if errors.Is(err, ErrDomainIPNotFound) {
				// get whois value while raw text contains keyword that represent WHOIS not found
				status.RespType = RespTypeNotFound
				result <- whoisStruct
				return
			}
			if IsParsePanicErr(err) {
				status.RespType = RespTypeParseError
				result <- whoisStruct
				return
			}
			if errors.Is(err, ErrTimeout) {
				status.RespType = RespTypeTimeout
			} else {
				status.RespType = RespTypeError
			}
			close(result)
			return
		}
		status.RespType = RespTypeFound
		result <- whoisStruct
	}()
	return result
}

// QueryIPRaw query whois server with IP
func (c *Client) QueryIPRaw(ctx context.Context, ip, whoisServer string) (*Raw, error) {
	whoisDst := FmtWhoisServer(whoisServer, c.whoisPort)
	rawtext, err := c.getText(ctx, whoisDst, ip)
	if err != nil {
		return NewRaw("", whoisServer), err
	}
	return NewRaw(rawtext, whoisServer), nil
}

// ParseIP get parser and parse rawtext
func (c *Client) ParseIP(ip string, wrt *Raw) (pip *wip.Whois, err error) {
	parser := wip.NewParser(ip, c.logger)
	defer func() {
		if panicErr := recover(); panicErr != nil {
			c.logger.WithField("ip", ip).Warnf("panic when parsing raw text: %v", panicErr)
			// still return rawtext and server when parsing failed
			pip = wip.NewWhois(nil, wrt.Rawtext, wrt.Server)
			err = fmt.Errorf("parse error: %s", panicErr.(string))
		}
	}()
	// Log for panic to avoid crashing server
	parsedWhois, err := parser.Do(wrt.Rawtext)
	if err != nil {
		return nil, err
	}
	pip = wip.NewWhois(parsedWhois, wrt.Rawtext, wrt.Server)
	if wip.WhoisNotFound(wrt.Rawtext) {
		return pip, ErrDomainIPNotFound
	}
	return pip, nil
}

// QueryIP get whois information from given whois server or query 'whois.arin.net' and parse 'OrgId'
// to get the organization and map to the whois server, query again if it's not 'whois.arin.net'
func (c *Client) QueryIP(ctx context.Context, ip string, whoisServers ...string) (*wip.Whois, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var wrt *Raw
	var orgid string
	var err error
	if len(whoisServers) > 0 && len(whoisServers[0]) > 0 {
		if wrt, err = c.QueryIPRaw(ctx, ip, whoisServers[0]); err != nil {
			if utils.IsTimeout(err) {
				return nil, ErrTimeout
			}
			return nil, fmt.Errorf("get whois error: %w", err)
		}
	} else {
		rawtext, err := c.getText(ctx, c.arinServAddr, "n "+ip)
		if err != nil {
			if utils.IsTimeout(err) {
				return nil, ErrTimeout
			}
			return nil, err
		}
		orgid = wd.FoundByKey("OrgId", rawtext)
		if ws, ok := c.arinMap[orgid]; ok {
			if wrt, err = c.QueryIPRaw(ctx, ip, ws); err != nil {
				if utils.IsTimeout(err) {
					return nil, ErrTimeout
				}
				return nil, fmt.Errorf("get whois error: %w", err)
			}
		} else {
			wrt = NewRaw(rawtext, c.arinServAddr[:strings.Index(c.arinServAddr, ":")])
		}
	}
	pip, err := c.ParseIP(ip, wrt)
	// panic when parsing, pip.ParsedWhois = nil
	if IsParsePanicErr(err) {
		return pip, err
	}
	if wip.WhoisNotFound(wrt.Rawtext) {
		return pip, ErrDomainIPNotFound
	}
	if err != nil {
		return nil, err
	}
	return pip, nil
}

// QueryIPChan performs query and returns channel for caller to wait for the result
func (c *Client) QueryIPChan(status *Status) chan *wip.Whois {
	result := make(chan *wip.Whois)
	go func() {
		whoisStruct, err := c.QueryIP(context.Background(), status.DomainOrIP, status.WhoisServer)
		if err != nil {
			status.Err = err
			if errors.Is(err, ErrDomainIPNotFound) {
				// get whois value while raw text contains keyword that represent WHOIS not found
				status.RespType = RespTypeNotFound
				result <- whoisStruct
				return
			}
			if IsParsePanicErr(err) {
				status.RespType = RespTypeParseError
				result <- whoisStruct
				return
			}
			if errors.Is(err, ErrTimeout) {
				status.RespType = RespTypeTimeout
			} else {
				status.RespType = RespTypeError
			}
			close(result)
			return
		}
		status.RespType = RespTypeFound
		result <- whoisStruct
	}()
	return result
}
