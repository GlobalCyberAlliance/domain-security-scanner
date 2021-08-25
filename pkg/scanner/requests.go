package scanner

import (
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"strings"
)

func (s *Scanner) getDNSAnswers(domain string, recordType uint16) ([]dns.RR, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), recordType)

	in, _, err := s.dc.Exchange(req, s.GetNS())
	if err != nil {
		return nil, err
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

	for _, ans := range answers {
		if t, ok := ans.(*dns.AAAA); ok {
			records = append(records, t.AAAA.String())
		}
	}

	return records, nil
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

func (s *Scanner) getTypeDKIM(name string) (string, error) {
	if s.DKIMSelector == "" {
		s.DKIMSelector = "x"
	}

	for _, dname := range []string{
		s.DKIMSelector + "._domainkey." + name,
		name,
	} {
		txtRecords, err := s.getTypeTXT(dname)
		if err != nil {
			return "", nil
		}

		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, DKIMPrefix) {
				return txt, nil
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

		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, DMARCPrefix) {
				return txt, nil
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
		answer.Header().Rrtype = dns.TypeTXT
		if t, ok := answer.(*dns.TXT); ok {
			for _, txt := range t.Txt {
				records = append(records, txt)
			}
		}
	}

	return records, nil
}
