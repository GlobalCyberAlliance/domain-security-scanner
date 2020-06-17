# GCA DMARC Risk Scanner
The DMARC Risk Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records.  The scan results will provide the raw DNS record for each protocol, if the record exists.  A Web API is also available if organizations would like to perform a single domain scan for DKIM, DMARC or SPF at [https://dmarcguide.globalcyberalliance.org](https://dmarcguide.globalcyberalliance.org).

## Download
You can download pre-compiled binaries for macOS, Linux and Windows from the [releases](https://github.com/GlobalCyberAlliance/GCADMARCRiskScanner/releases) page.

Alternatively, you can run the binary from within our pre-built Docker image:
 
```shell
docker run docker.pkg.github.com/globalcyberalliance/gcadmarcriskscanner/gcadmarcriskscanner:latest
```

## Build

To build this application, you'll need [Go](https://golang.org/) installed.

```shell
git clone https://github.com/GlobalCyberAlliance/GCADMARCRiskScanner.git
cd GCADMARCRiskScanner
go build -o drs
```

This will output a binary called `drs`. You can then move it or use it by running `./drs` (on Unix devices).

## Find a Specific Record From a Single Domain
To scan a domain for a specific type of record (DKIM, DMARC or SPF), run:

`drs single [domain] <type>`

Example:

`drs single globalcyberalliance.org dkim --selector gca`

*Note: You **need** to spcify the `selector` flag if you're querying a DKIM record.*

## Bulk Scan Domains

Scan any number of domains for DMARC and SPF records. By default, this listens on `STDIN`, meaning you run the command via `drs bulk` and then enter each domain one-by-one.

Alternatively, you can specify multiple domains at runtime:

`drs bulk globalcyberalliance.org github.com google.com`

Or you can provide [RFC 1035](https://tools.ietf.org/html/rfc1035) zone files by piping with the `-z` flag enabled:

`drs bulk -z < /path/to/zonefile`

See the zonefile.example file in this repo.

### Flags

`-c` `--concurrent` The number of domains to scan concurrently.

`-d` `--dns` Use one or multiple of our predefined DNS ranges (Cloudflare, Google, Level3, OpenDNS, Quad9).

`-n` `--nameservers` Use one or multiple manually specified nameservers in `host[:port]` format.

`-p` `--progress` Show a progress bar (disabled when reading from STDIN).

`-t` `--timeout` Timeout duration for a DNS query.

`-z` `--zonefile` Pipe a [RFC 1035](https://tools.ietf.org/html/rfc1035) zone file as the input for the bulk command.

## License

This repository is licensed under the Apache License version 2.0.

Some of the project's dependencies may be under different licenses.
