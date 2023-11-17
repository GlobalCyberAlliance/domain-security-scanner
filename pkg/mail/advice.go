package mail

import (
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
	"github.com/matcornic/hermes/v2"
)

// PrepareEmail accepts a scanner.ScanResult and returns a hermes.Email object
func (s *Server) PrepareEmail(result *scanner.ScanResult) hermes.Email {
	var mailServers string

	entries := s.domainAdvice(result)

	email := hermes.Email{
		Body: hermes.Body{
			Title:      "Your email security scan results:",
			Dictionary: entries,
			Signature:  "Thanks",
			Outros: []string{
				"For more information, visit our comprehensive mail security guide at https://dmarcguide.globalcyberalliance.org",
			},
		},
	}

	for _, server := range result.MX {
		if mailServers == "" {
			mailServers = server
		} else {
			mailServers = mailServers + "\n" + server
		}
	}

	email.Body.Table = hermes.Table{
		Data: [][]hermes.Entry{
			{
				{Key: "Test", Value: "DOMAIN"},
				{Key: "Result", Value: result.Domain},
			},
			{
				{Key: "Test", Value: "BIMI"},
				{Key: "Result", Value: result.BIMI},
			},
			{
				{Key: "Test", Value: "DKIM"},
				{Key: "Result", Value: result.DKIM},
			},
			{
				{Key: "Test", Value: "DMARC"},
				{Key: "Result", Value: result.DMARC},
			},
			{
				{Key: "Test", Value: "MX"},
				{Key: "Result", Value: mailServers},
			},
			{
				{Key: "Test", Value: "SPF"},
				{Key: "Result", Value: result.SPF},
			},
		},
	}

	return email
}

func (s *Server) domainAdvice(result *scanner.ScanResult) (entries []hermes.Entry) {
	advice := s.advisor.CheckAll(result.BIMI, result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF, s.CheckTls)

	entries = append(entries, hermes.Entry{
		Key:   "Domain",
		Value: stringify(advice["domain"]),
	})

	entries = append(entries, hermes.Entry{
		Key:   "BIMI",
		Value: stringify(advice["bimi"]),
	})

	entries = append(entries, hermes.Entry{
		Key:   "DKIM",
		Value: stringify(advice["dkim"]),
	})

	entries = append(entries, hermes.Entry{
		Key:   "DMARC",
		Value: stringify(advice["dmarc"]),
	})

	entries = append(entries, hermes.Entry{
		Key:   "MX",
		Value: stringify(advice["mx"]),
	})

	entries = append(entries, hermes.Entry{
		Key:   "SPF",
		Value: stringify(advice["spf"]),
	})

	return entries
}
