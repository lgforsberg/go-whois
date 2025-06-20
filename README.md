# Go-Whois Library

[![Go Report Card](https://goreportcard.com/badge/github.com/lgforsberg/go-whois)](https://goreportcard.com/report/github.com/lgforsberg/go-whois)
[![GoDoc](https://godoc.org/github.com/lgforsberg/go-whois?status.svg)](https://godoc.org/github.com/lgforsberg/go-whois)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fork of a comprehensive Go library for querying WHOIS information for domains and IP addresses. The fork extends the original library with additional TLD parsers and security improvements.

## Features

- **Domain WHOIS Queries**: Support for 100+ TLDs with custom parsers
- **IP Address WHOIS**: Query IP address information from RIRs (ARIN, RIPE, APNIC, etc.)
- **Security Hardened**: Protection against memory exhaustion attacks and timeouts
- **Robust Error Handling**: Comprehensive error handling and input validation
- **High Performance**: Efficient parsing with proper resource management

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
- **Legacy**: `.com`, `.net`, `.org`, `.info`, `.biz`, `.mobi`, `.name`, `.pro`
- **New**: `.aero`, `.coop`, `.museum`, `.jobs`, `.travel`, `.cat`, `.tel`, `.xxx`, `.post`, `.asia`, `.edu`, `.gov`, `.mil`
- **Modern**: `.link`, `.blog`, `.app`, `.dev`, `.io`, and many more

### ccTLDs with Custom Parsers
`.am`, `.ar`, `.as`, `.at`, `.au`, `.aw`, `.be`, `.bg`, `.br`, `.cl`, `.cn`, `.cr`, `.cz`, `.de`, `.dk`, `.ee`, `.eu`, `.fi`, `.fr`, `.gg`, `.hk`, `.hr`, `.hu`, `.im`, `.is`, `.ir`, `.it`, `.je`, `.jp`, `.kr`, `.kz`, `.lt`, `.lu`, `.lv`, `.md`, `.mk`, `.mo`, `.mx`, `.nl`, `.nu`, `.no`, `.pf`, `.pl`, `.pt`, `.qa`, `.ro`, `.rs`, `.ru`, `.sa`, `.se`, `.si`, `.sk`, `.sm`, `.sn`, `.su`, `.tg`, `.th`, `.tm`, `.tk`, `.ml`, `.gq`, `.tn`, `.tr`, `.tz`, `.ug`, `.uz`, `.ve`, `.vu`, `.tw`, `.ua`, `.uk`

### ccTLDs using Default Parser (Standard ICANN Format)
`.ac`, `.af`, `.ag`, `.bi`, `.co`, `.io`, `.ca`, `.cc`, `.cx`, `.dm`, `.fm`, `.fo`, `.gd`, `.gi`, `.gl`, `.gy`, `.ie`, `.ke`, `.ki`, `.kn`, `.ky`, `.la`, `.lc`, `.ma`, `.me`, `.mg`, `.mn`, `.mu`, `.mz`, `.nf`, `.ng`, `.nz`, `.om`, `.pe`, `.pr`, `.pw`, `.sc`, `.sh`, `.sl`, `.so`, `.st`, `.sy`, `.tl`, `.us`, `.ws`, `.hn`

### Unsupported TLDs
These TLDs have no whois server, restricted whois access, or servers that refuse connections (handled by default parser):
`.ad`, `.ae`, `.ai`, `.ch`, `.es`, `.gs`, `.hm`, `.ht`, `.il`, `.in`, `.li`, `.ms`, `.mc`, `.na`, `.nc`, `.pm`, `.ps`, `.re`, `.rw`, `.sx`, `.tc`, `.tf`, `.to`, `.wf`, `.yt`, `.vc`, `.uy`, `.vg`, `.vi`, `.vn`, `.sb`, `.ly`, `.id`

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Adding New TLD Parsers

To add support for a new TLD:

1. Create a new file `whois/domain/tld.go` (replace `tld` with the actual TLD)
2. Implement the `ITLDParser` interface
3. Add the parser to the `NewTLDDomainParser` function in `parser.go`
4. Add test cases in `whois/domain/tld_test.go`
5. Add test data in `whois/domain/testdata/tld/`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original repository: [shlin168/go-whois](https://github.com/shlin168/go-whois)
- WHOIS server list: [whois-server-list](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml)
- Public suffix list: [publicsuffix.org](https://publicsuffix.org/)

## Fork Improvements

### New Parsers Added
- `.pt`, `.de`, `.dk`, `.se`, `.nu`, `.no`, `.bg`, `.ee`, `.gg`, `.je`, `.hr`, `.hu`, `.im`, `.is`, `.lt`, `.lu`, `.lv`, `.md`, `.mk`, `.ro`, `.rs`, `.si`, `.sm`, `.su`, `.jp`, `.cn`, `.hk`, `.kr`, `.kz`, `.mo`, `.mx`, `.pf`, `.qa`, `.sa`, `.sn`, `.th`, `.tm`, `.tn`, `.tr`, `.tz`, `.ug`, `.uz`, `.ve`, `.vu`

### Additional Changes
- Changed whois server associated with `.pt` from `whois.ripe.net` to `whois.dns.pt`
- Removed whois server associated with `.mc`. Was `whois.ripe.net` but there is no official whois server for `.mc`
- Fixed critical security vulnerabilities: added size limits to prevent memory exhaustion attacks, added HTTP timeouts, and fixed unsafe type assertions
- Improved error handling in TLD parsers (`.hu`, `.au`, `.kr`) with input validation and proper date parsing
- Refactoring of custom parsers and their respective tests to decrase function complexity.
  
---

*This fork maintains compatibility with usage of the original library while adding security improvements and extended TLD support.* 