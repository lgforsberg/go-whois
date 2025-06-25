package domain

const (
	// WhoisTimeFmt is time format for CreatedDate, UpdatedDate and ExpiredDate
	WhoisTimeFmt = "2006-01-02T15:04:05+00:00"
)

// Whois represents the complete WHOIS response for a domain query.
// It contains both the parsed structured data and the original raw text response.
type Whois struct {
	ParsedWhois *ParsedWhois `json:"parsed,omitempty"`
	WhoisServer string       `json:"whois_server,omitempty"` // whois server which response the rawtext
	RawText     string       `json:"rawtext,omitempty"`
	IsAvailable *bool        `json:"available,omitempty"`
}

// ParsedWhois represents the structured data extracted from a WHOIS response.
// It contains domain registration information including dates, contacts, and technical details.
type ParsedWhois struct {
	DomainName     string     `json:"domain,omitempty"`
	Registrar      *Registrar `json:"registrar,omitempty"`
	NameServers    []string   `json:"name_servers,omitempty"`
	CreatedDate    string     `json:"created_date,omitempty"` // in WhoisTimeFmt format
	CreatedDateRaw string     `json:"-"`                      // if it's not valid time format
	UpdatedDate    string     `json:"updated_date,omitempty"` // in WhoisTimeFmt format
	UpdatedDateRaw string     `json:"-"`                      // if it's not valid time format
	ExpiredDate    string     `json:"expired_date,omitempty"` // in WhoisTimeFmt format
	ExpiredDateRaw string     `json:"-"`                      // if it's not valid time format
	Statuses       []string   `json:"statuses,omitempty"`
	Dnssec         string     `json:"dnssec,omitempty"`
	Contacts       *Contacts  `json:"contacts,omitempty"`
}

// Registrar represents the organization responsible for managing a domain registration.
// It includes contact information and identifiers for the registrar.
type Registrar struct {
	IanaID            string `json:"iana_id,omitempty"`
	Name              string `json:"name,omitempty"`
	AbuseContactEmail string `json:"abuse_contact_email,omitempty"`
	AbuseContactPhone string `json:"abuse_contact_phone,omitempty"`
	WhoisServer       string `json:"whois_server,omitempty"` // whois server parsed from rawtext
	URL               string `json:"url,omitempty"`
}

// Contact represents contact information for a domain entity.
// This includes personal/organizational details and contact methods.
type Contact struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name,omitempty"`
	Email        string   `json:"email,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Country      string   `json:"country,omitempty"`
	City         string   `json:"city,omitempty"`
	Street       []string `json:"street,omitempty"`
	State        string   `json:"state,omitempty"`
	Postal       string   `json:"postal,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	PhoneExt     string   `json:"phone_ext,omitempty"`
	Fax          string   `json:"fax,omitempty"`
	FaxExt       string   `json:"fax_ext,omitempty"`
}

// Contacts holds the different types of contacts associated with a domain.
// Each contact type may be nil if the information is not available in the WHOIS response.
type Contacts struct {
	Registrant *Contact `json:"registrant,omitempty"` // nil if information not found
	Admin      *Contact `json:"admin,omitempty"`      // nil if information not found
	Tech       *Contact `json:"tech,omitempty"`       // nil if information not found
	Billing    *Contact `json:"billing,omitempty"`    // nil if information not found
}

// NewWhois creates a new Whois instance with the given parsed data, raw text, and server information.
// This is typically used internally by the WHOIS client after parsing a response.
func NewWhois(pw *ParsedWhois, rawtext, whoisServer string) *Whois {
	return &Whois{ParsedWhois: pw, RawText: rawtext, WhoisServer: whoisServer}
}
