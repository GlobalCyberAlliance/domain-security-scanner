# GCA DMARC Risk Scanner
The DMARC Risk Scanner can be used to perform scans against domain(s) for DMARC, SPF and DKIM DNS records.  The scan results will provide the raw DNS record for each protocol, if the record exists.  A Web API is also available if organizations would like to perform a single domain scan for DKIM, DMARC and/or SPF at [https://dmarcguide.globalcyberalliance.org](https://dmarcguide.globalcyberalliance.org).

## Build
To build the application run `make` in the root directory. Alternatively use

`go build -o bin/drs github.com/GlobalCyberAlliance/DMARC-Risk-Scanner/cmd/drs`

## SPF
Scan a domain for an SPF record.

`drs spf [domain]`

## DMARC
Scan a domain for a DMARC record.

`drs dmarc [domain]`

## DKIM
Scan a domain for a DKIM record.

`drs dkim [domain] [dkim_selector]`

## Bulk
Scan any number of domains for SPF and DMARC records. Defaults to STDIN.

#### Flags
`--opendns` Use OpenDNS's nameservers

`--google` Use Google's nameservers

`--level3` Use Level3's nameservers

`-n` `--nameservers` Use specific nameservers, in `host[:port]` format; may be specified multiple times

`-t` `--timeout` Timeout duration for a DNS query

`-c` `--concurrent` The number of domains to scan concurrently

`-z` `--zonefile` Input file/pipe contains an RFC 1035 zone file

`-p` `--progress` Show a progress bar (disabled when reading from STDIN)

## License
This repository is licensed under the Apache License version 2.0.

Some of the project's dependencies may be under different licenses.
