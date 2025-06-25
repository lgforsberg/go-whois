# Go-Whois Library

[![Go Report Card](https://goreportcard.com/badge/github.com/lgforsberg/go-whois)](https://goreportcard.com/report/github.com/lgforsberg/go-whois)
[![GoDoc](https://godoc.org/github.com/lgforsberg/go-whois?status.svg)](https://godoc.org/github.com/lgforsberg/go-whois)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fork of a an excellent Go library by https://github.com/shlin168 for querying WHOIS information for domains and IP addresses. The fork extends the original library with additional TLD parsers, new parser utilty functions for repeating patterns, and implements a few security improvements. Most parts of the code base has been touched up to lower function complexity. It does however maintain the library usage interface and output format. 

## Features
- **Domain WHOIS Queries**: Support for 100+ TLDs with custom parsers
- **IP Address WHOIS**: Query IP address information from RIRs (ARIN, RIPE, APNIC, etc.)
- **Security Hardened**: Protection against memory exhaustion attacks and timeouts
- **Robust Error Handling**: Comprehensive error handling and input validation
- **High Performance**: Efficient parsing with proper resource management

## New in v1.1.0 is: 
- **Unified handling of Available Flag**: Domain Names not found, not registered or "available" now all have the available flag set to "true" reliably across all supported TLDs. 
- **Updated Tests with new test data**: Added many new tests of the function of the whois domain library as well as test case data to make use of them.
- **Improved documentation of functions**: In-code documentation of functions have been added where previously missing. 
- **Improved adherence to go code quality standards**: Adherence to recommendations from gofmt, gocyclo, govet etc has been improved.

## Past versions

### New in v1.0.1 was: 
- Changed whois server associated with `.pt` from `whois.ripe.net` to `whois.dns.pt`
- Removed whois server associated with `.mc`. Was `whois.ripe.net` which is clearly not the case.
- Fixed security vulnerabilities: 
  - Added size limits to prevent memory exhaustion attacks 
  - Added HTTP timeouts
  - Fixed unsafe type assertions
- Improved error handling in TLD parsers (f.ex. `.hu`, `.au`, `.kr`) with input validation and proper date parsing.
- Refactored many functions and their respective tests to decrease overall function complexity.
  
## Installation

```bash
go get github.com/lgforsberg/go-whois
```

## Quick Start

### Domain WHOIS Query

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/lgforsberg/go-whois/whois"
)

func main() {
    client, err := whois.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    result, err := client.Query(ctx, "google.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Domain: %s\n", result.ParsedWhois.DomainName)
    fmt.Printf("Registrar: %s\n", result.ParsedWhois.Registrar.Name)
    fmt.Printf("Created: %s\n", result.ParsedWhois.CreatedDate)
    fmt.Printf("Expires: %s\n", result.ParsedWhois.ExpiredDate)
}
```

### IP Address WHOIS Query

```go
func main() {
    client, err := whois.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    result, err := client.QueryIP(ctx, "8.8.8.8")
    if err != nil {
        log.Fatal(err)
    }

    for _, network := range result.ParsedWhois.Networks {
        fmt.Printf("Network: %s\n", network.Inetnum)
        fmt.Printf("Organization: %s\n", network.Org)
    }
}
```

## Supported TLDs

### All gTLDs (Generic Top-Level Domains)
Both Legacy and New gTLDs are supported by the default parser:

`.com`, `.net`, `.org`, `.info`, `.biz`, `.mobi`, `.name`, `.pro`, `.aero`, `.coop`, `.museum`, `.jobs`, `.travel`, `.cat`, `.tel`, `.xxx`, `.post`, `.asia`, `.edu`, `.gov`, `.mil`, `.link`, `.blog`, `.app`, `.dev`, `.shop`, and all the rest too.

### ccTLDs using Default Parser (Standard ICANN Format)
These TLDs implement the standard ICANN format even though they are ccTLDs and will be handled by the default parser. Good Work! We like these:

`.ac`, `.af`, `.ag`, `.bi`, `.co`, `.io`, `.ca`, `.cc`, `.cx`, `.dm`, `.fm`, `.fo`, `.gd`, `.gi`, `.gl`, `.gy`, `.ie`, `.ke`, `.ki`, `.kn`, `.ky`, `.la`, `.lc`, `.ma`, `.me`, `.mg`, `.mn`, `.mu`, `.mz`, `.nf`, `.ng`, `.nz`, `.om`, `.pe`, `.pr`, `.pw`, `.sc`, `.sh`, `.sl`, `.so`, `.st`, `.sy`, `.tl`, `.us`, `.ws`, `.hn`

### ccTLDs with Custom Parsers
These TLDs have custom whois output formats and the level of detail will vary between each one:

`.am`, `.ar`, `.as`, `.at`, `.au`, `.aw`, `.be`, `.bg`, `.br`, `.cl`, `.cn`, `.cr`, `.cz`, `.de`, `.dk`, `.ee`, `.eu`, `.fi`, `.fr`, `.gg`, `.hk`, `.hr`, `.hu`, `.im`, `.is`, `.ir`, `.it`, `.je`, `.jp`, `.kr`, `.kz`, `.lt`, `.lu`, `.lv`, `.md`, `.mk`, `.ml`, `.mo`, `.mx`, `.nl`, `.nu`, `.no`, `.pf`, `.pl`, `.pt`, `.qa`, `.ro`, `.rs`, `.ru`, `.sa`, `.se`, `.si`, `.sk`, `.sm`, `.sn`, `.su`, `.tg`, `.th`, `.tk`, `.tm`, `.tn`, `.tr`, `.tz`, `.ug`, `.uz`, `.ve`, `.vu`, `.tw`, `.ua`, `.uk`

### Unsupported TLDs
These TLDs have no whois server, no proper whois informatio, restricted whois access, servers that refuse connections, or cannot be queried for some other reason:

`.ad`, `.ae`, `.ai`, `.ch`, `.es`, `.gs`, `.gq`, `.hm`, `.ht`, `.il`, `.in`, `.li`, `.ms`, `.mc`, `.na`, `.nc`, `.pm`, `.ps`, `.re`, `.rw`, `.sx`, `.tc`, `.tf`, `.to`, `.wf`, `.yt`, `.vc`, `.uy`, `.vg`, `.vi`, `.vn`, `.sb`, `.ly`, `.id`

**Note**: `.gq` (Equatorial Guinea) is currently defunct due to a dispute between the government and the registry backend provider. The TLD has no functional WHOIS server.

If you do get an answer, it will be parsed by the default parser, which may or may not work as intended.

## Advanced Usage

### Custom WHOIS Server

```go
client, err := whois.NewClient()
if err != nil {
    log.Fatal(err)
}

// Query specific WHOIS server
result, err := client.Query(ctx, "example.com", "whois.example.com")
```

### Custom Timeouts

```go
client, err := whois.NewClient(
    whois.WithTimeout(10 * time.Second),
)
```

### Raw WHOIS Data

```go
raw, err := client.QueryRaw(ctx, "example.com")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Raw WHOIS data:\n%s\n", raw.Rawtext)
```

## API Reference

### Client Methods

| Method | Description |
|--------|-------------|
| `Query(ctx, domain)` | Query domain WHOIS information |
| `QueryIP(ctx, ip)` | Query IP address WHOIS information |
| `QueryRaw(ctx, domain)` | Get raw WHOIS response |
| `QueryIPRaw(ctx, ip)` | Get raw IP WHOIS response |

### ParsedWhois Structure

```go
type ParsedWhois struct {
    DomainName     string     `json:"domain,omitempty"`
    Registrar      *Registrar `json:"registrar,omitempty"`
    NameServers    []string   `json:"name_servers,omitempty"`
    CreatedDate    string     `json:"created_date,omitempty"`
    UpdatedDate    string     `json:"updated_date,omitempty"`
    ExpiredDate    string     `json:"expired_date,omitempty"`
    Statuses       []string   `json:"statuses,omitempty"`
    Dnssec         string     `json:"dnssec,omitempty"`
    Contacts       *Contacts  `json:"contacts,omitempty"`
}
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run specific test categories:

```bash
# Domain parser tests
go test ./whois/domain/...

# Client tests
go test ./whois/...

# IP parser tests
go test ./whois/ip/...
```

### Adding New TLD Parsers

To add support for a new TLD:

1. Create a new file `whois/domain/tld.go` (replace `tld` with the actual TLD)
2. Implement the `ITLDParser` interface
3. Add the parser to the `NewTLDDomainParser` function in `parser.go`
4. Add test cases in `whois/domain/tld_test.go`
5. Add test data in `whois/domain/testdata/tld/`

## License

This project is licensed under the MIT License by the original author, and the same license is extended and honored by the fork maintainer - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original repository: [shlin168/go-whois](https://github.com/shlin168/go-whois)
- WHOIS server list: [whois-server-list](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml)
- Public suffix list: [publicsuffix.org](https://publicsuffix.org/)

## Fork Improvements

### New Parsers Added
- `.pt`, `.de`, `.dk`, `.se`, `.nu`, `.no`, `.bg`, `.ee`, `.gg`, `.je`, `.hr`, `.hu`, `.im`, `.is`, `.lt`, `.lu`, `.lv`, `.md`, `.mk`, `.ro`, `.rs`, `.si`, `.sm`, `.su`, `.jp`, `.cn`, `.hk`, `.kr`, `.kz`, `.mo`, `.mx`, `.pf`, `.qa`, `.sa`, `.sn`, `.th`, `.tm`, `.tn`, `.tr`, `.tz`, `.ug`, `.uz`, `.ve`, `.vu`