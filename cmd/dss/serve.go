package main

import (
	"time"

	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/advisor"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/http"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/mail"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(cmdServe)
	cmdServe.AddCommand(cmdServeAPI)
	cmdServe.AddCommand(cmdServeMail)

	cmdServeAPI.Flags().IntVarP(&port, "port", "p", 8080, "Specify the port for the API to listen on")

	cmdServeMail.Flags().StringVar(&mailConfig.Inbound.Host, "inboundHost", "", "Incoming mail host and port")
	cmdServeMail.Flags().StringVar(&mailConfig.Inbound.Pass, "inboundPass", "", "Incoming mail password")
	cmdServeMail.Flags().StringVar(&mailConfig.Inbound.User, "inboundUser", "", "Incoming mail username")
	cmdServeMail.Flags().DurationVar(&interval, "interval", 30, "Set the mail check interval in seconds")
	cmdServeMail.Flags().StringVar(&mailConfig.Outbound.Host, "outboundHost", "", "Outgoing mail host and port")
	cmdServeMail.Flags().StringVar(&mailConfig.Outbound.Pass, "outboundPass", "", "Outgoing mail password")
	cmdServeMail.Flags().StringVar(&mailConfig.Outbound.User, "outboundUser", "", "Outgoing mail username")

	if err := setRequiredFlags(cmdServeMail, "inboundHost", "inboundPass", "inboundUser", "outboundHost", "outboundPass", "outboundUser"); err != nil {
		log.Fatal().Err(err).Msg("unable to set required flags for 'serve mail' command")
	}
}

var (
	interval   time.Duration
	port       int
	mailConfig mail.Config

	cmdServe = &cobra.Command{
		Use:   "serve",
		Short: "Serve the scanner via a REST API or dedicated mailbox",
		Run: func(command *cobra.Command, args []string) {
			_ = command.Help()
		},
	}

	cmdServeAPI = &cobra.Command{
		Use:   "api",
		Short: "Serve DNS security queries via a dedicated API",
		Run: func(command *cobra.Command, args []string) {
			server := http.NewServer(log)

			opts := []scanner.ScannerOption{
				scanner.ConcurrentScans(concurrent),
				scanner.UseCache(cacheEnabled),
				scanner.UseNameservers(nameservers),
				scanner.WithDNSBuffer(dnsBuffer),
				scanner.WithTimeout(time.Duration(timeout) * time.Second),
			}

			sc, err := scanner.New(opts...)
			if err != nil {
				log.Fatal().Err(err).Msg("could not create domain scanner")
			}

			server.Advisor = advisor.NewAdvisor(time.Duration(timeout)*time.Second, cacheEnabled)
			server.CheckTls = checkTls
			server.Scanner = sc

			server.Serve(port)
		},
	}

	cmdServeMail = &cobra.Command{
		Use:   "mail",
		Short: "Serve DNS security queries via a dedicated email account",
		Run: func(command *cobra.Command, args []string) {
			opts := []scanner.ScannerOption{
				scanner.ConcurrentScans(concurrent),
				scanner.UseCache(cacheEnabled),
				scanner.UseNameservers(nameservers),
				scanner.WithDNSBuffer(dnsBuffer),
				scanner.WithTimeout(time.Duration(timeout) * time.Second),
			}

			sc, err := scanner.New(opts...)
			if err != nil {
				log.Fatal().Err(err).Msg("could not create scanner")
			}

			mailServer, err := mail.NewMailServer(mailConfig, log, sc, advisor.NewAdvisor(time.Duration(timeout)*time.Second, cacheEnabled))
			if err != nil {
				log.Fatal().Err(err).Msg("could not open mail server connection")
			}

			mailServer.CheckTls = checkTls

			mailServer.Serve(interval)
		},
	}
)
