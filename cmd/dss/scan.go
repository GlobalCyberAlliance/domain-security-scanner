package main

import (
	"os"
	"strings"
	"time"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domain_advisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/model"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(cmdScan)
}

var cmdScan = &cobra.Command{
	Use:     "scan [flags] <STDIN>",
	Example: "  dss scan <STDIN>\n  dss scan globalcyberalliance.org gcaaide.org google.com\n  dss scan -z < zonefile",
	Short:   "Scan DNS records for one or multiple domains.",
	Long:    "Scan DNS records for one or multiple domains.\nBy default, the command will listen on STDIN, allowing you to type or pipe multiple domains.",
	Run: func(command *cobra.Command, args []string) {
		opts := []scanner.ScannerOption{
			scanner.ConcurrentScans(concurrent),
			scanner.UseCache(cache),
			scanner.UseNameservers(nameservers),
			scanner.WithTimeout(time.Duration(timeout) * time.Second),
		}

		var source scanner.Source

		if len(args) == 0 && zoneFile {
			source = scanner.ZonefileSource(os.Stdin)
		} else if len(args) > 0 && zoneFile {
			log.Fatal().Msg("-z flag provided, but not reading from STDIN")
		} else if len(args) == 0 {
			log.Info().Msg("Accepting input from STDIN. Type a domain and hit enter.")
			source = scanner.TextSource(os.Stdin)
		} else {
			sr := strings.NewReader(strings.Join(args, "\n"))
			source = scanner.TextSource(sr)
		}

		sc, err := scanner.New(opts...)
		if err != nil {
			log.Fatal().Err(err).Msg("An unexpected error occurred.")
		}

		sc.DKIMSelector = dkimSelector
		sc.RecordType = recordType

		for result := range sc.Start(source) {
			if advise {
				advice := domainAdvisor.CheckAll(result.BIMI, result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF, checkTls)
				printToConsole(model.ScanResultWithAdvice{
					ScanResult: result,
					Advice:     advice,
				})
			} else {
				printToConsole(result)
			}
		}
	},
}
