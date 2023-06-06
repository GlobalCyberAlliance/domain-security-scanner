package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	cmd = &cobra.Command{
		Use:     "dss",
		Short:   "Scan a domain's DNS records.",
		Long:    "Scan a domain's DNS records.\nhttps://github.com/GlobalCyberAlliance/DomainSecurityScanner",
		Version: "2.2.0",
	}
	log                        = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	concurrent                 int
	dkimSelector, recordType   string
	nameservers                []string
	timeout                    int64
	advise, checkTls, zoneFile bool
)

func main() {
	cmd.PersistentFlags().BoolVarP(&advise, "advise", "a", false, "Provide suggestions for incorrect/missing mail security features")
	cmd.PersistentFlags().BoolVar(&cache, "cache", false, "Cache scan results for 60 seconds")
	cmd.PersistentFlags().BoolVar(&checkTls, "checkTls", false, "Check the TLS connectivity and cert validity of domains")
	cmd.PersistentFlags().IntVarP(&concurrent, "concurrent", "c", runtime.NumCPU(), "The number of domains to scan concurrently")
	cmd.PersistentFlags().StringVarP(&dkimSelector, "dkimSelector", "d", "x", "Specify a DKIM selector")
	cmd.PersistentFlags().StringVarP(&format, "format", "f", "yaml", "Format to print results in (yaml, json)")
	cmd.PersistentFlags().StringSliceVarP(&nameservers, "nameservers", "n", nil, "Use specific nameservers, in `host[:port]` format; may be specified multiple times")
	cmd.PersistentFlags().StringVarP(&recordType, "type", "r", "sec", "Type of DNS record to lookup (a, aaaa, cname, mx, sec [DKIM/DMARC/SPF], txt")
	cmd.PersistentFlags().Int64VarP(&timeout, "timeout", "t", 15, "Timeout duration for a DNS query")
	cmd.PersistentFlags().BoolVarP(&zoneFile, "zonefile", "z", false, "Input file/pipe containing an RFC 1035 zone file")

	_ = cmd.Execute()
}

func marshal(data interface{}) (output []byte) {
	switch strings.ToLower(format) {
	case "json":
		output, _ = json.Marshal(data)
	case "jsonp":
		output, _ = json.MarshalIndent(data, "", "\t")
	default:
		output, _ = yaml.Marshal(data)
	}

	return output
}

func printToConsole(data interface{}) {
	marshalledData := marshal(data)

	print(string(marshalledData))
}

func printToFile(data interface{}, file string) {
	marshalledData := marshal(data)

	outputFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return
	}
	defer outputFile.Close()

	outputFile.Write(marshalledData)
}

func setRequiredFlags(command *cobra.Command, flags ...string) error {
	for _, flag := range flags {
		if err := command.MarkFlagRequired(flag); err != nil {
			return err
		}
	}

	return nil
}
