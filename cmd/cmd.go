package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"os"
)

var (
	DNS         []string
	Nameservers []string
	Root        = &cobra.Command{
		Use:     "drs",
		Short:   "Scan a domain for SPF, DMARC, or DKIM records.",
		Long:    "Scan a domain for SPF, DMARC, or DKIM records.\nhttps://github.com/GlobalCyberAlliance/GCADMARCRiskScanner",
		Version: "2.0.0",
		PersistentPreRun: func(command *cobra.Command, args []string) {
			SetNameservers()
		},
	}
	Timeout int64
)

func init() {
	Root.PersistentFlags().StringSliceVarP(&DNS, "dns", "d", nil, "Use predefined nameservers (cloudflare, google, level3, opendns, quad9).")
	Root.PersistentFlags().StringSliceVarP(&Nameservers, "nameservers", "n", nil, "Use specific nameservers, in `host[:port]` format; may be specified multiple times.")
	Root.PersistentFlags().Int64VarP(&Timeout, "timeout", "t", 15, "Timeout duration for a DNS query.")
}

func Check(command *cobra.Command, args []string) {
	if len(args) == 0 {
		_ = command.Help()
		os.Exit(0)
	} else {
		return
	}
}

func SetNameservers() {
	if len(DNS) > 0 {
		for _, provider := range DNS {
			switch provider {
			case "cloudflare":
				Nameservers = append(Nameservers, []string{"1.1.1.1:53", "1.0.0.1:53"}...)
			case "google":
				Nameservers = append(Nameservers, []string{"8.8.8.8:53", "8.8.4.4:53"}...)
			case "level3":
				Nameservers = append(Nameservers, []string{"4.2.2.1:53", "4.2.2.2:53", "4.2.2.3:53", "4.2.2.4:53", "4.2.2.5:53", "4.2.2.6:53"}...)
			case "opendns":
				Nameservers = append(Nameservers, []string{"208.67.222.222:53", "208.67.220.220:53"}...)
			case "quad9":
				Nameservers = append(Nameservers, []string{"9.9.9.9:53", "149.112.112.112:53"}...)
			default:
				log.Fatal("Provider " + provider + " does not exist")
			}
		}
	} else {
		Nameservers = []string{"9.9.9.9:53"}
	}
}
