package scanner

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

const (
	DefaultBIMIPrefix  = "v=BIMI1;"
	DefaultDKIMPrefix  = "v=DKIM1;"
	DefaultDMARCPrefix = "v=DMARC1;"
	DefaultSPFPrefix   = "v=spf1 "
)

var (
	BIMIPrefix  = DefaultBIMIPrefix
	DKIMPrefix  = DefaultDKIMPrefix
	DMARCPrefix = DefaultDMARCPrefix
	SPFPrefix   = DefaultSPFPrefix

	// knownDkimSelectors is a list of known DKIM selectors.
	knownDkimSelectors = []string{
		"x",             // Generic
		"google",        // Google
		"selector1",     // Microsoft
		"selector2",     // Microsoft
		"k1",            // MailChimp
		"mandrill",      // Mandrill
		"everlytickey1", // Everlytic
		"everlytickey2", // Everlytic
		"dkim",          // Hetzner
		"mxvault",       // MxVault
	}
)

// getDNSRecords queries the DNS server for records of a specific type for a domain.
// It returns a slice of strings (the records) and an error if any occurred.
func (s *Scanner) getDNSRecords(domain string, recordType uint16) (records []string, err error) {
	answers, err := s.getDNSAnswers(domain, recordType)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		if answer.Header().Rrtype == dns.TypeCNAME {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupTxt, err := s.getDNSRecords(t.Target, recordType)
				if err != nil {
					return nil, fmt.Errorf("failed to recursively lookup txt record for %v: %w", t.Target, err)
				}

				records = append(records, recursiveLookupTxt...)

				continue
			}

			answer.Header().Rrtype = recordType
		}

		switch t := answer.(type) {
		case *dns.A:
			records = append(records, t.A.String())
		case *dns.AAAA:
			records = append(records, t.AAAA.String())
		case *dns.MX:
			records = append(records, t.Mx)
		case *dns.NS:
			records = append(records, t.Ns)
		case *dns.TXT:
			records = append(records, t.Txt...)
		}
	}

	return records, nil
}

// getDNSAnswers queries the DNS server for answers to a specific question.
// It returns a slice of dns.RR (DNS resource records) and an error if any occurred.
func (s *Scanner) getDNSAnswers(domain string, recordType uint16) ([]dns.RR, error) {
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), recordType)
	req.SetEdns0(s.dnsBuffer, true) // increases the response buffer size

	in, _, err := s.dnsClient.Exchange(req, s.getNS())
	if err != nil {
		return nil, err
	}

	if in.MsgHdr.Truncated && s.dnsBuffer < 4096 {
		s.logger.Warn().Msg(fmt.Sprintf("DNS buffer %v was too small for %v, retrying with larger buffer (4096)", s.dnsBuffer, domain))

		req.SetEdns0(4096, true)

		in, _, err = s.dnsClient.Exchange(req, s.getNS())
		if err != nil {
			return nil, err
		}
	}

	return in.Answer, nil
}

// GetDNSRecords is a convenience wrapper which will scan all provided DNS record types
// and fill the pointered ScanResult. It returns an error if any occurred.
func (s *Scanner) GetDNSRecords(scanResult *Result, recordTypes ...string) (err error) {
	for _, recordType := range recordTypes {
		switch strings.ToUpper(recordType) {
		case "BIMI":
			scanResult.BIMI, err = s.getTypeBIMI(scanResult.Domain)
		case "DKIM":
			scanResult.DKIM, err = s.getTypeDKIM(scanResult.Domain)
		case "DMARC":
			scanResult.DMARC, err = s.getTypeDMARC(scanResult.Domain)
		case "MX":
			scanResult.MX, err = s.getDNSRecords(scanResult.Domain, dns.TypeMX)
		case "NS":
			scanResult.NS, err = s.getDNSRecords(scanResult.Domain, dns.TypeNS)
		case "SPF":
			scanResult.SPF, err = s.getTypeSPF(scanResult.Domain)
		default:
			return errors.New("invalid dns record type")
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Scanner) getTypeBIMI(domain string) (string, error) {
	for _, dname := range []string{
		"default._bimi." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT)
		if err != nil {
			return "", nil
		}

		for index, record := range records {
			if strings.HasPrefix(record, BIMIPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeDKIM queries the DNS server for DKIM records of a domain.
// It returns a string (DKIM record) and an error if any occurred.
func (s *Scanner) getTypeDKIM(domain string) (string, error) {
	selectors := append(s.dkimSelectors, knownDkimSelectors...)

	for _, selector := range selectors {
		records, err := s.getDNSRecords(selector+"._domainkey."+domain, dns.TypeTXT)
		if err != nil {
			return "", nil
		}

		for index, record := range records {
			if strings.HasPrefix(record, DKIMPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeDMARC queries the DNS server for DMARC records of a domain.
// It returns a string (DMARC record) and an error if any occurred.
func (s *Scanner) getTypeDMARC(domain string) (string, error) {
	for _, dname := range []string{
		"_dmarc." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT)
		if err != nil {
			return "", nil
		}

		for index, record := range records {
			if strings.HasPrefix(record, DMARCPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeSPF queries the DNS server for SPF records of a domain.
// It returns a string (SPF record) and an error if any occurred.
func (s *Scanner) getTypeSPF(domain string) (string, error) {
	records, err := s.getDNSRecords(domain, dns.TypeTXT)
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if strings.HasPrefix(record, SPFPrefix) {
			if !strings.Contains(record, "redirect=") {
				return record, nil
			}

			parts := strings.Fields(record)
			for _, part := range parts {
				if strings.Contains(part, "redirect=") {
					redirectDomain := strings.TrimPrefix(part, "redirect=")
					return s.getTypeSPF(redirectDomain)
				}
			}
		}
	}

	return "", nil
}
