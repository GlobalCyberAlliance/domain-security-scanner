package scanner

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
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

func (s *Scanner) getDNSAnswers(domain string, recordType uint16) ([]dns.RR, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), recordType)
	req.SetEdns0(s.dnsBuffer, true) // increases the response buffer size

	in, _, err := s.dc.Exchange(req, s.GetNS())
	if err != nil {
		return nil, err
	}

	if in.MsgHdr.Truncated && s.dnsBuffer <= 4096 {
		fmt.Printf("DNS buffer %v was too small for %v, retrying with larger buffer (4096)\n", s.dnsBuffer, domain)

		req.SetEdns0(4096, true)

		in, _, err = s.dc.Exchange(req, s.GetNS())
		if err != nil {
			return nil, err
		}
	}

	return in.Answer, nil
}

// GetDNSRecords is a convenience wrapper which will scan all provided DNS record types
// and fill the pointered ScanResult
func (s *Scanner) GetDNSRecords(scanResult *ScanResult, recordTypes ...string) (err error) {
	for _, recordType := range recordTypes {
		switch strings.ToUpper(recordType) {
		case "A":
			scanResult.A, err = s.getTypeA(scanResult.Domain)
		case "AAAA":
			scanResult.AAAA, err = s.getTypeAAAA(scanResult.Domain)
		case "BIMI":
			scanResult.BIMI, err = s.getTypeBIMI(scanResult.Domain)
		case "CNAME":
			scanResult.CNAME, err = s.getTypeCNAME(scanResult.Domain)
		case "DKIM":
			scanResult.DKIM, err = s.getTypeDKIM(scanResult.Domain)
		case "DMARC":
			scanResult.DMARC, err = s.getTypeDMARC(scanResult.Domain)
		case "MX":
			scanResult.MX, err = s.getTypeMX(scanResult.Domain)
		case "SPF":
			scanResult.SPF, err = s.getTypeSPF(scanResult.Domain)
		case "TXT":
			scanResult.TXT, err = s.getTypeTXT(scanResult.Domain)
		default:
			return errors.New("invalid dns record type")
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Scanner) getTypeA(domain string) (records []string, err error) {
	answers, err := s.getDNSAnswers(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		if t, ok := answer.(*dns.A); ok {
			records = append(records, t.A.String())
		}
	}

	return records, nil
}

func (s *Scanner) getTypeAAAA(domain string) (records []string, err error) {
	answers, err := s.getDNSAnswers(domain, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		if t, ok := answer.(*dns.AAAA); ok {
			records = append(records, t.AAAA.String())
		}
	}

	return records, nil
}

func (s *Scanner) getTypeBIMI(domain string) (string, error) {
	for _, dname := range []string{
		"default._bimi." + domain,
		domain,
	} {
		txtRecords, err := s.getTypeTXT(dname)
		if err != nil {
			return "", nil
		}

		for index, txt := range txtRecords {
			if strings.HasPrefix(txt, BIMIPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(txtRecords[index:], ""), nil
			}
		}
	}

	return "", nil
}

func (s *Scanner) getTypeCNAME(domain string) (string, error) {
	answers, err := s.getDNSAnswers(domain, dns.TypeCNAME)
	if err != nil {
		return "", err
	}

	for _, answer := range answers {
		if t, ok := answer.(*dns.CNAME); ok {
			return t.String(), err
		}
	}

	return "", nil
}

func (s *Scanner) getTypeDKIM(domain string) (string, error) {
	selectors := append(s.DKIMSelectors, knownDkimSelectors...)

	for _, selector := range selectors {
		txtRecords, err := s.getTypeTXT(selector + "._domainkey." + domain)
		if err != nil {
			return "", nil
		}

		for index, txt := range txtRecords {
			if strings.HasPrefix(txt, DKIMPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(txtRecords[index:], ""), nil
			}
		}
	}

	return "", nil
}

func (s *Scanner) getTypeDMARC(domain string) (string, error) {
	for _, dname := range []string{
		"_dmarc." + domain,
		domain,
	} {
		txtRecords, err := s.getTypeTXT(dname)
		if err != nil {
			return "", nil
		}

		for index, txt := range txtRecords {
			if strings.HasPrefix(txt, DMARCPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(txtRecords[index:], ""), nil
			}
		}
	}

	return "", nil
}

func (s *Scanner) getTypeMX(domain string) (records []string, err error) {
	answers, err := s.getDNSAnswers(domain, dns.TypeMX)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		if t, ok := answer.(*dns.MX); ok {
			records = append(records, t.Mx)
		}
	}

	return records, nil
}

func (s *Scanner) getTypeSPF(domain string) (string, error) {
	txtRecords, err := s.getTypeTXT(domain)
	if err != nil {
		return "", err
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, SPFPrefix) {
			if !strings.Contains(txt, "redirect=") {
				return txt, nil
			}

			parts := strings.Fields(txt)
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

func (s *Scanner) getTypeTXT(domain string) (records []string, err error) {
	answers, err := s.getDNSAnswers(domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		// handle recursive lookups
		if answer.Header().Rrtype == dns.TypeCNAME {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupTxt, err := s.getTypeTXT(t.Target)
				if err != nil {
					return nil, fmt.Errorf("failed to recursively lookup txt record for %v: %w", t.Target, err)
				}

				records = append(records, recursiveLookupTxt...)

				continue
			}
		}

		answer.Header().Rrtype = dns.TypeTXT
		if t, ok := answer.(*dns.TXT); ok {
			for _, txt := range t.Txt {
				records = append(records, txt)
			}
		}
	}

	return records, nil
}
