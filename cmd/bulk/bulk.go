package bulk

import (
	"encoding/json"
	"github.com/GlobalCyberAlliance/GCADMARCRiskScanner/cmd"
	"github.com/GlobalCyberAlliance/GCADMARCRiskScanner/pkg/scanner"
	"github.com/spf13/cobra"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

func init() {
	cmd.Root.AddCommand(cmdBulk)

	cmdBulk.Flags().IntVarP(&batchSize, "concurrent", "c", runtime.NumCPU(), "The number of domains to scan concurrently.")
	cmdBulk.Flags().BoolVarP(&zoneFile, "zonefile", "z", false, "Input file/pipe contains an RFC 1035 zone file.")
	cmdBulk.Flags().BoolVarP(&showProgress, "progress", "p", false, "Show a progress bar (disabled when reading from STDIN)")
}

var (
	batchSize    int
	zoneFile     bool
	showProgress bool

	cmdBulk = &cobra.Command{
		Use:     "bulk [flags] <STDIN>",
		Example: "  drs bulk <STDIN>\n  drs bulk globalcyberalliance.org gcaaide.org google.com --dns quad9\n  drs bulk -z < zonefile",
		Short:   "Scan multiple domains for DMARC and SPF records, outputted as JSON.",
		Long:    "Scan multiple domains for DMARC and SPF records, outputted as JSON.\nBy default, the command will listen on STDIN, allowing you to type or pipe multiple domains.",
		Run: func(command *cobra.Command, args []string) {
			opts := []scanner.ScannerOption{
				scanner.ConcurrentScans(batchSize),
				scanner.UseNameservers(cmd.Nameservers),
				scanner.WithTimeout(time.Duration(cmd.Timeout) * time.Second),
			}

			// Decide where we want to read the list of domain names from.
			// If there are no arguments, read from STDIN.
			var source scanner.Source

			if len(args) == 0 && zoneFile {
				source = scanner.ZonefileSource(os.Stdin)
			} else if len(args) > 0 && zoneFile {
				log.Fatalln("error: -z flag provided, but not reading from STDIN")
			} else if len(args) == 0 {
				source = scanner.TextSource(os.Stdin)
			} else {
				sr := strings.NewReader(strings.Join(args, "\n"))
				source = scanner.TextSource(sr)
			}

			sc, err := scanner.New(opts...)
			if err != nil {
				log.Fatalln(err)
			}

			// Set up a *json.Encoder that encodes scan results to STDOUT.
			jsenc := json.NewEncoder(os.Stdout)
			for result := range sc.Start(source) {
				if err := jsenc.Encode(result); err != nil {
					log.Fatalln("error encoding scan result:", err)
				}
			}
		},
	}
)
