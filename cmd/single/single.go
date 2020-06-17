package single

import (
	"context"
	"errors"
	"fmt"
	"github.com/GlobalCyberAlliance/GCADMARCRiskScanner/cmd"
	"github.com/spf13/cobra"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

func init() {
	cmd.Root.AddCommand(cmdSingle)

	cmdSingle.Flags().StringVarP(&dkimSelector, "selector", "s", "", "DKIM record selector.")
}

var (
	dkimSelector string
	recordType   string
	resolver     *net.Resolver
	results      []string

	cmdSingle = &cobra.Command{
		Use:     "single [domain] <type>",
		Example: "  drs single globalcyberalliance.org --dns quad9\n  drs single globalcyberalliance.org dkim --selector gca",
		Short:   "Scan one domain for DKIM, DMARC or SPF records.",
		Run: func(command *cobra.Command, args []string) {
			cmd.Check(command, args)

			rawDomain, err := url.Parse(args[0])
			if err != nil {
				log.Fatalln("Please enter a valid domain:", err)
			}

			var domain string

			if rawDomain.Scheme == "http" || rawDomain.Scheme == "https" {
				domain = rawDomain.Host
			} else {
				domain = rawDomain.Path
			}

			if len(args) > 1 {
				recordType = strings.ToUpper(args[1])

				switch recordType {
				case "DKIM":
					if dkimSelector == "" {
						log.Fatalln("Please specify the DKIM selector via --selector.")
					}
					domain = dkimSelector + "._domainkey." + domain
				case "DMARC":
					domain = "_dmarc." + domain
				case "SPF":
					domain = domain
				default:
					log.Fatalln("Invalid record type: " + recordType)
				}
			}

			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Duration(cmd.Timeout) * time.Second,
					}
					return d.DialContext(ctx, "udp", cmd.Nameservers[0])
				},
			}

			if recordType != "" {
				fmt.Println(recordType)
				results, _ = request(domain, recordType)
			} else {
				parsedResults, _ := request("_dmarc."+domain, "DMARC")
				results = append(results, parsedResults...)

				parsedResults, _ = request(domain, "SPF")
				results = append(results, parsedResults...)
			}

			if len(results) == 0 {
				fmt.Println("No records found.")
			} else {
				for _, v := range results {
					fmt.Println(v)
				}
			}
		},
	}
)

func request(domain string, rType string) ([]string, error) {
	var parsedResults []string

	if rawResults, err := resolver.LookupTXT(context.Background(), domain); err != nil {
		return nil, err
	} else {
		for _, v := range rawResults {
			if rType != "" {
				if strings.Contains(v, rType) || strings.Contains(v, strings.ToLower(rType)) {
					parsedResults = append(parsedResults, []string{v}...)
				}
			} else {
				parsedResults = append(parsedResults, []string{v}...)
			}
		}
	}

	if len(parsedResults) == 0 {
		return nil, errors.New("No records found.")
	}

	return parsedResults, nil
}
