package main

import (
	"os"
	"strings"
	"time"

	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/advisor"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/model"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
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
			scanner.WithCache(cacheEnabled),
			scanner.WithConcurrentScans(concurrent),
			scanner.WithDKIMSelectors(dkimSelector...),
			scanner.WithDNSBuffer(dnsBuffer),
			scanner.WithNameservers(nameservers),
			scanner.WithTimeout(time.Duration(timeout) * time.Second),
		}

		var source scanner.Source

		if len(args) == 0 && zoneFile {
			source = scanner.NewSource(os.Stdin, scanner.ZonefileSourceType)
		} else if len(args) > 0 && zoneFile {
			log.Fatal().Msg("-z flag provided, but not reading from STDIN")
		} else if len(args) == 0 {
			log.Info().Msg("Accepting input from STDIN. Type a domain and hit enter.")
			source = scanner.NewSource(os.Stdin, scanner.TextSourceType)
		} else {
			reader := strings.NewReader(strings.Join(args, "\n"))
			source = scanner.NewSource(reader, scanner.TextSourceType)
		}

		sc, err := scanner.New(opts...)
		if err != nil {
			log.Fatal().Err(err).Msg("An unexpected error occurred.")
		}

		domainAdvisor := advisor.NewAdvisor(time.Duration(timeout)*time.Second, cacheEnabled)

		if format == "csv" && outputFile == "" {
			log.Info().Msg("CSV header: domain,A,AAAA,BIMI,CNAME,DKIM,DMARC,MX,SPF,TXT,duration,error,advice")
		}

		for result := range sc.Start(source) {
			resultWithAdvice := model.ScanResultWithAdvice{
				ScanResult: result,
			}

			if result.Error == "" && advise {
				resultWithAdvice.Advice = domainAdvisor.CheckAll(result.BIMI, result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF, checkTls)
			}

			printToConsole(resultWithAdvice)
		}
	},
}
