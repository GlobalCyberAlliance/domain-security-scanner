package main

/*
 * Copyright 2018 Global Cyber Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITION OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/GlobalCyberAlliance/DMARC-Risk-Scanner/scanner"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

var (
	useOpenDNS, useGoogleDNS, useLevel3DNS bool
	nameservers                            []string
	timeout                                time.Duration
	batchSize                              int
	zonep                                  bool
	showProgress                           bool
	verbose                                bool
	rootCmd                                = &cobra.Command{
		Use:   "drs",
		Short: "Scan a domain for SPF, DMARC, or DKIM records.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	spfCmd = &cobra.Command{
		Use:   "spf [domain]",
		Short: "Scan a domain for an SPF record.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runScan("SPF", args[0], "")
		},
	}
	dmarcCmd = &cobra.Command{
		Use:   "dmarc [domain]",
		Short: "Scan a domain for a DMARC record.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runScan("DMARC", args[0], "")
		},
	}
	dkimCmd = &cobra.Command{
		Use:   "dkim [domain] [selector]",
		Short: "Scan a domain for an DKIM record given a specific selector.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			runScan("DKIM", args[0], args[1])
		},
	}
	bulkCmd = &cobra.Command{
		Use:   "bulk",
		Short: "Scan any number of domains for SPF and DMARC records. Defaults to STDIN",
		Run: func(cmd *cobra.Command, args []string) {
			runBulkScan()
		},
	}
)

func main() {
	bulkCmd.Flags().BoolVar(&useOpenDNS, "opendns", false, "Use OpenDNS's nameservers")
	bulkCmd.Flags().BoolVar(&useGoogleDNS, "google", false, "Use Google's nameservers")
	bulkCmd.Flags().BoolVar(&useLevel3DNS, "level3", false, "Use Level3's nameservers")
	bulkCmd.Flags().StringSliceVarP(&nameservers, "nameservers", "n", nil, "Use specific nameservers, in `host[:port]` format; may be specified multiple times")
	bulkCmd.Flags().DurationVarP(&timeout, "timeout", "t", 15*time.Second, "Timeout duration for a DNS query")
	bulkCmd.Flags().IntVarP(&batchSize, "concurrent", "c", runtime.NumCPU(), "The number of domains to scan concurrently")
	bulkCmd.Flags().BoolVarP(&zonep, "zonefile", "z", false, "Input file/pipe contains an RFC 1035 zone file")
	bulkCmd.Flags().BoolVarP(&showProgress, "progress", "p", false, "Show a progress bar (disabled when reading from STDIN)")

	rootCmd.AddCommand(
		spfCmd,
		dmarcCmd,
		dkimCmd,
		bulkCmd,
	)
	rootCmd.Execute()
}

// runScan scans a domain for one of three record types based on argument input.
// Domains are formatted to match the RFC specifications of each record type.
// SPF - RFC7208, DMARC - RFC7489, DKIM - RFC4871
func runScan(record string, domain string, selector string) {
	var d string

	u, err := url.Parse(domain)
	if err != nil {
		log.Fatalln("Please enter a valid domain:", err)
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		d = u.Host
	} else {
		d = u.Path
	}

	switch record {
	case "SPF":
		d = d
	case "DMARC":
		d = "_dmarc." + d
	case "DKIM":
		d = selector + "._domainkey." + d
	}

	results, err := net.LookupTXT(d)
	if err != nil {
		log.Fatalln("An error occured scanning domain for", record, "records:", err)
	}
	for _, v := range results {
		if strings.Contains(v, record) || strings.Contains(v, strings.ToLower(record)) {
			fmt.Println(v)
		}
	}
}

// runBulkScan scans multiple domains from STDIN by default.
// DNS services can be specified, as well as different input methods.
// Outputs to STDOUT by default.
func runBulkScan() {
	opts := []scanner.ScannerOption{
		scanner.WithTimeout(timeout),
		scanner.ConcurrentScans(batchSize),
	}

	if useOpenDNS {
		nameservers = append(nameservers, scanner.OpenDNS...)
	}
	if useGoogleDNS {
		nameservers = append(nameservers, scanner.GoogleDNS...)
	}
	if useLevel3DNS {
		nameservers = append(nameservers, scanner.Level3...)
	}
	opts = append(opts, scanner.UseNameservers(nameservers))

	// Decide where we want to read the list of domain names from.
	//
	// If there are no arguments, read from STDIN.
	var source scanner.Source
	if flag.NArg() == 0 && zonep {
		source = scanner.ZonefileSource(os.Stdin)
	} else if flag.NArg() > 0 && zonep {
		fmt.Fprintln(os.Stderr, "error: -z flag provided, but not reading from STDIN")
		os.Exit(1)
	} else if flag.NArg() == 0 {
		source = scanner.TextSource(os.Stdin)
	} else {
		sr := strings.NewReader(strings.Join(flag.Args(), "\n"))
		source = scanner.TextSource(sr)
	}
	sc, err := scanner.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// Set up a *json.Encoder that encodes scan results to STDOUT.
	jsenc := json.NewEncoder(os.Stdout)
	for result := range sc.Start(source) {
		if err := jsenc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "error encoding scan result:", err)
		}
	}
}
