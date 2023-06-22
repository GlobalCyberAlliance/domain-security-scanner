package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	cmd = &cobra.Command{
		Use:     "dss",
		Short:   "Scan a domain's DNS records.",
		Long:    "Scan a domain's DNS records.\nhttps://github.com/GlobalCyberAlliance/DomainSecurityScanner",
		Version: "2.2.3",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			getConfig()
			if len(nameservers) == 0 {
				nameservers = cfg.Nameservers
			}
		},
	}
	cfg                                            *Config
	log                                            = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	concurrent                                     int
	dkimSelector, format, recordType               string
	nameservers                                    []string
	timeout                                        int64
	advise, cache, checkTls, writeToFile, zoneFile bool
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
	cmd.PersistentFlags().BoolVarP(&writeToFile, "writetofile", "w", false, "Write the output to a file")
	cmd.PersistentFlags().BoolVarP(&zoneFile, "zonefile", "z", false, "Input file/pipe containing an RFC 1035 zone file")

	_ = cmd.Execute()
}

func getConfig() {
	configDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal().Err(err).Msg("unable to retrieve user's home directory")
	}

	configDir = strings.TrimSuffix(configDir, "/") + "/.config/domain-security-scanner"

	viper.AddConfigPath(configDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.SetDefault("nameservers", "8.8.8.8")

	if err = viper.ReadInConfig(); err != nil {
		if err = os.MkdirAll(configDir, os.ModePerm); err != nil {
			log.Fatal().Err(err).Msg("failed to create config directory")
		}

		if _, err = os.Create(configDir + "/config.yml"); err != nil {
			log.Fatal().Err(err).Msg("unable to create config")
		}

		if err = viper.WriteConfig(); err != nil {
			log.Fatal().Err(err).Msg("No config file could be found, and one could not be created.")
		}

		if err = viper.ReadInConfig(); err != nil {
			log.Fatal().Err(err).Msg("No config file could be found.")
		}
	} else {
		_ = viper.WriteConfig() // Write any environmental variables to the config file
	}

	if err = viper.Unmarshal(&cfg); err != nil {
		log.Fatal().Err(err).Msg("unable to set config values")
	}
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
	if writeToFile {
		extension := format
		if extension == "jsonp" {
			extension = "json"
		}

		filename := cast.ToString(time.Now().Unix()) + "." + extension
		printToFile(data, filename)
		log.Info().Msg("Output written to " + filename)
		return
	}

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

	if _, err = outputFile.Write(marshalledData); err != nil {
		log.Fatal().Err(err).Msg("failed to write output to file")
	}
}

func setRequiredFlags(command *cobra.Command, flags ...string) error {
	for _, flag := range flags {
		if err := command.MarkFlagRequired(flag); err != nil {
			return err
		}
	}

	return nil
}
