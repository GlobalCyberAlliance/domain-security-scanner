# Domain Security Scanner
The Domain Security Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records. You can also serve this functionality via an API, or a dedicated mailbox. A web application is also available if organizations would like to perform a single domain scan for DKIM, DMARC or SPF at [https://dmarcguide.globalcyberalliance.org](https://dmarcguide.globalcyberalliance.org).

## Download
You can download pre-compiled binaries for macOS, Linux and Windows from the [releases](https://github.com/GlobalCyberAlliance/DomainSecurityScanner/releases) page.

Alternatively, you can run the binary from within our pre-built Docker image:

```shell
docker run ghcr.io/globalcyberalliance/domainsecurityscanner/domainsecurityscanner:latest
```

## Build

To build this application, you'll need [Go](https://golang.org/) installed.

```shell
git clone https://github.com/GlobalCyberAlliance/DomainSecurityScanner.git
cd DomainSecurityScanner
make
```

This will output a binary called `dss`. You can then move it or use it by running `./bin/dss` (on Unix devices).

## Find a Specific Record From a Single Domain
To scan a domain for a specific type of record (A, AAAA, CNAME, DKIM, DMARC, MX, SPF, TXT), run:

`dss scan [domain] --type dmarc`

Example:

`dss scan globalcyberalliance.org --dkimSelector gca`

*Note: You may not receive your DKIM record unless you specify the `dkimSelector` flag.*

## Bulk Scan Domains

Scan any number of domains' DNS records. By default, this listens on `STDIN`, meaning you run the command via `dss scan` and then enter each domain one-by-one.

Alternatively, you can specify multiple domains at runtime:

`dss scan globalcyberalliance.org github.com google.com`

Or you can provide [RFC 1035](https://tools.ietf.org/html/rfc1035) zone files by piping with the `-z` flag enabled:

`dss scan -z < /path/to/zonefile`

See the zonefile.example file in this repo.

## Serve REST API

You can also expose the domain scanning functionality via a REST API. By default, this is rate limited to 10 requests per second from a single IP address. Serve the API by runing the following:

`dss serve api --port 80`

You can then get a single domain's results by submitting a GET request like this `http://server-ip:port/api/v1/scan/globalcyberalliance.org`, which will return a JSON response similar to this:

```json
{
    "domain": "globalcyberalliance.org",
    "spf": "v=spf1 include:_u.globalcyberalliance.org._spf.smart.ondmarc.com -all",
    "dmarc": "v=DMARC1; p=reject; fo=1; rua=mailto:3941b663@inbox.ondmarc.com,mailto:2zw1qguv@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:2zw1qguv@fr.dmarcian.com,mailto:gca-ny-sc@globalcyberalliance.org;",
    "dkim": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqPnV7+e5SuK77YHtzO815h/qofRr/ZCnCzER9CnHQX3HXfmVrhWoCMG6p4HpWVN1uZhsuqMdeOtwzh4DCvlb2D7BDoQAbTUdb9tEZ1sY4pOqUgYfjVLmJXztN8HfLj2fbqvOZEnUPNNHb4RGouSFUBpLsTMTCodIfF/xSZfGNZQIDAQAB",
    "duration": 2174200,
    "mx": [
      "aspmx.l.google.com.",
      "alt4.aspmx.l.google.com.",
      "alt2.aspmx.l.google.com.",
      "alt3.aspmx.l.google.com.",
      "alt1.aspmx.l.google.com."
    ],
    "advice": {
    "dkim": [
      "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly."
    ],
    "dmarc": [
      "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed."
    ],
    "domain": null,
    "mx": null,
    "spf": null
    }
}
```

Alternatively, you can scan multiple domains by POSTing them to http://server-ip:port/api/v1/scan with a request body like this:

```json
{
  "domains": [
    "gcatoolkit.org",
    "globalcyberalliance.org"
  ]
}
```

Which will return a JSON response like this:

```json
[
  {
    "domain": "globalcyberalliance.org",
    "spf": "v=spf1 include:_u.globalcyberalliance.org._spf.smart.ondmarc.com -all",
    "dmarc": "v=DMARC1; p=reject; fo=1; rua=mailto:3941b663@inbox.ondmarc.com,mailto:2zw1qguv@ag.dmarcian.com,mailto:dmarc_agg@vali.email; ruf=mailto:2zw1qguv@fr.dmarcian.com,mailto:gca-ny-sc@globalcyberalliance.org;",
    "dkim": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqPnV7+e5SuK77YHtzO815h/qofRr/ZCnCzER9CnHQX3HXfmVrhWoCMG6p4HpWVN1uZhsuqMdeOtwzh4DCvlb2D7BDoQAbTUdb9tEZ1sY4pOqUgYfjVLmJXztN8HfLj2fbqvOZEnUPNNHb4RGouSFUBpLsTMTCodIfF/xSZfGNZQIDAQAB",
    "duration": 17322000,
    "mx": [
      "aspmx.l.google.com.",
      "alt4.aspmx.l.google.com.",
      "alt2.aspmx.l.google.com.",
      "alt3.aspmx.l.google.com.",
      "alt1.aspmx.l.google.com."
    ],
    "advice": {
      "DKIM": [
        "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly."
      ],
      "DMARC": [
        "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed."
      ],
      "DOMAIN": null,
      "MX": null,
      "SPF": null
    }
  },
  {
    "domain": "gcatoolkit.org",
    "spf": "v=spf1 -all",
    "dmarc": "v=DMARC1; p=reject;",
    "duration": 77997100,
    "mx": [
      "mx00.1and1.com.",
      "mx01.1and1.com."
    ],
    "advice": {
      "DKIM": [
        "We couldn't detect any active DKIM record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this."
      ],
      "DMARC": [
        "You are at the highest level! However, we do recommend keeping reports enabled (via the rua tag) in case any issues may arise and you can review reports to see if DMARC is the cause."
      ],
      "DOMAIN": null,
      "MX": null,
      "SPF": null
    }
  }
]
```

## Serve Dedicated Mailbox

You can also serve scan results via a dedicated mailbox. It is advised that you use this mailbox for this sole purpose, as all emails will be deleted at each 10 second interval.

```shell
dss serve mail --inboundHost "imap.gmail.com:993" --inboundPass "SomePassword" --inboundUser "SomeAddress@domain.tld" --outboundHost "smtp.gmail.com:587" --outboundPass "SomePassword" --outboundUser "SomeAddress@domain.tld"
```

You can then email this inbox from any address, and you'll receive an email back with your scan results.

### Flags

`-c` `--concurrent` The number of domains to scan concurrently (default 12)

`-d` `--dkimSelector` Specify a DKIM selector (default "x").

`-f` `--format` Format to print results in (human, json) (default "human").

`-n` `--nameservers` Use specific nameservers, in host[:port] format; may be specified multiple times.

`-t` `--timeout` Timeout duration for a DNS query (default 15).

`-r` `--type` Type of DNS record to lookup (A, AAAA, CNAME, MX, SEC [DKIM/DMARC/SPF], TXT (default "SEC").

`-z` `--zonefile` Input file/pipe containing an [RFC 1035](https://tools.ietf.org/html/rfc1035) zone file.

## License

This repository is licensed under the Apache License version 2.0.

Some of the project's dependencies may be under different licenses.
