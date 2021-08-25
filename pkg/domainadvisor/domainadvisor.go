package domainadvisor

import (
	"regexp"
	"strings"
)

var (
	emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

func CheckAll(dkim string, dmarc string, domain string, mx []string, spf string) (advice map[string][]string) {
	advice = make(map[string][]string)

	advice["DKIM"] = CheckDKIM(dkim)
	advice["DMARC"] = CheckDMARC(dmarc)
	advice["DOMAIN"] = CheckDomain(domain)
	advice["MX"] = CheckMX(mx)
	advice["SPF"] = CheckSPF(spf)

	return advice
}

func CheckDKIM(dkim string) (advice []string) {
	if dkim == "" {
		advice = append(advice, "We couldn't detect any active DKIM record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this.")
	} else {
		advice = append(advice, "DKIM is setup for this email server. However, if you have other 3rd party systems, please send a test email to confirm DKIM is setup properly.")
	}

	return advice
}

func CheckDMARC(dmarc string) (advice []string) {
	if len(dmarc) == 0 {
		advice = append(advice, "You do not have DMARC setup! Please visit https://dmarcguide.globalcyberalliance.org to set it up.")
		return advice
	}

	if strings.Contains(dmarc, ";") {
		dmarcResult := strings.Split(dmarc, ";")

		counter := 0
		for _, tag := range dmarcResult {
			counter++

			tag = strings.TrimSpace(tag)

			switch counter {
			case 1:
				if !strings.Contains(tag, "v=DMARC1") {
					advice = append(advice, "The beginning of your DMARC record should be v=DMARC1 with specific capitalization.")
				}
			case 2:
				if strings.Contains(tag, "p=") && !strings.Contains(tag, "sp=") {
					ruaExists := false
					tagValue := strings.TrimPrefix(tag, "p=")

					if strings.Contains(dmarc, "rua=") {
						ruaExists = true
					}

					switch tagValue {
					case "quarantine":
						if ruaExists {
							advice = append(advice, "You are currently at the second level and receiving reports. Please make sure to review the reports, make the appropriate adjustments, and move to reject soon.")
						} else {
							advice = append(advice, "You are currently at the second level. However, you must receive reports in order to determine if DKIM/DMARC/SPF are functioning correctly and move to the highest level (reject). Please add the ‘rua’ tag to your DMARC policy.")
						}
					case "none":
						if ruaExists {
							advice = append(advice, "You are currently at the lowest level and receiving reports, which is a great starting point. Please make sure to review the reports, make the appropriate adjustments, and move to either quarantine or reject soon.")
						} else {
							advice = append(advice, "You are currently at the lowest level, which is a great starting point. However, you must receive reports in order to determine if DKIM/DMARC/SPF are functioning correctly. Please add the ‘rua’ tag to your DMARC policy.")
						}
					case "reject":
						if ruaExists {
							advice = append(advice, "You are at the highest level! Please make sure to continue reviewing the reports and make the appropriate adjustments, if needed.")
						} else {
							advice = append(advice, "You are at the highest level! However, we do recommend keeping reports enabled (via the rua tag) in case any issues may arise and you can review reports to see if DMARC is the cause.")
						}
					default:
						advice = append(advice, "Invalid DMARC policy specified, the record must be p=none/p=quarantine/p=reject.")
					}
				} else {
					advice = append(advice, "The second tag in your DMARC record must be p=none/p=quarantine/p=reject.")
				}
			default:
				if strings.Contains(tag, "rua=") {
					trimmedTag := strings.TrimPrefix(tag, "rua=")
					tagArray := strings.Split(trimmedTag, ",")

					var invalidAddress, missingMailto bool
					for _, address := range tagArray {
						if !strings.Contains(address, "mailto:") {
							missingMailto = true
						} else {
							trimmedAddress := strings.TrimPrefix(address, "mailto:")
							if !validateEmail(trimmedAddress) {
								invalidAddress = true
							}
						}
					}

					if missingMailto {
						advice = append(advice, "Each email address under the rua tag should contain a mailto: prefix. Example: rua=mailto:dmarc@globalcyberalliance.org,mailto:dmarc2@globalcyberalliance.org.")
					}

					if invalidAddress {
						advice = append(advice, "Your rua tag contains invalid email addresses.")
					}
				}
			}
		}
	} else {
		advice = append(advice, "Your DMARC record appears to be malformed as no semicolons seem to be present.")
	}

	return advice
}

func CheckDomain(domain string) (advice []string) {
	if _, ok := consumerDomains[domain]; ok {
		advice = append(advice, "Consumer based accounts (i.e gmail.com, yahoo.com, etc) are controlled by the Vendor. They are responsible for setting DKIM, SPF and DMARC capabilities on their domains.")
	}
	return advice
}

func CheckMX(mx []string) (advice []string) {
	switch len(mx) {
	case 0:
		advice = append(advice, "You do not have any mail servers setup, so you cannot receive email at this domain.")
	case 1:
		advice = append(advice, "You have a single mail server setup, but it's recommended that you have at least two setup in case the first one fails.")
	}

	return advice
}

func CheckSPF(spf string) (advice []string) {
	if spf == "" {
		advice = append(advice, "We couldn't detect any active SPF record for your domain. Please visit https://dmarcguide.globalcyberalliance.org to fix this.")
		return advice
	}

	if strings.Contains(spf, "all") {
		if strings.Contains(spf, "+all") {
			advice = append(advice, "Your SPF record contains the +all tag. It is strongly recommended that this be changed to either -all or ~all. The +all tag allows for any system regardless of SPF to send mail on the organization’s behalf.")
		}
	} else {
		advice = append(advice, "Your SPF record is missing the all tag. Please visit https://dmarcguide.globalcyberalliance.org to fix this.")
	}

	return advice
}

func validateEmail(email string) bool {
	if len(email) < 3 && len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}
