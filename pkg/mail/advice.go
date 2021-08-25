package mail

import (
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domainadvisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/matcornic/hermes/v2"
)

// PrepareEmail
func PrepareEmail(result *scanner.ScanResult) hermes.Email {
	var mailServers string

	entries := domainAdvice(result)

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

	if entries[0].Key != "DOMAIN" {
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
	}

	return email
}

func domainAdvice(result *scanner.ScanResult) (entries []hermes.Entry) {
	var val string

	advice := domainadvisor.CheckAll(result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF)

	if val = stringify(advice["DOMAIN"]); val != "" {
		return append(entries, hermes.Entry{
			Key:   "DOMAIN",
			Value: val,
		})
	}

	if val = stringify(advice["DKIM"]); val == "" {
		val = "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly."
	}
	entries = append(entries, hermes.Entry{
		Key:   "DKIM",
		Value: val,
	})

	if val = stringify(advice["DMARC"]); val == "" {
		val = "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed."
	}
	entries = append(entries, hermes.Entry{
		Key:   "DMARC",
		Value: val,
	})

	if val = stringify(advice["MX"]); val == "" {
		val = "You have a multiple mail servers setup! No further action needed."
	}
	entries = append(entries, hermes.Entry{
		Key:   "MX",
		Value: val,
	})

	if val = stringify(advice["SPF"]); val == "" {
		val = "SPF seems to be setup correctly!"
	}
	entries = append(entries, hermes.Entry{
		Key:   "SPF",
		Value: val,
	})

	return entries
}
