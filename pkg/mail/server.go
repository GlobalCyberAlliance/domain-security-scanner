package mail

import (
	"strings"
	"time"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

type Server struct {
	config   Config
	interval time.Duration
	logger   zerolog.Logger
	CheckTls bool
	Scanner  *scanner.Scanner
}

// NewMailServer returns a new instance of a mail server
func NewMailServer(config Config, logger zerolog.Logger, sc *scanner.Scanner) (*Server, error) {
	s := Server{
		config:  config,
		logger:  logger,
		Scanner: sc,
	}

	client, err := s.Login()
	if err != nil {
		return nil, err
	}
	defer client.Logout()

	return &s, nil
}

func (s *Server) Serve(interval time.Duration) {
	s.interval = interval

	s.logger.Info().Msg("Starting mail server on mailbox " + s.config.Inbound.User)
	s.logger.Info().Msg("Mail check interval set to " + cast.ToString(interval*time.Second))

	if err := s.handler(); err != nil {
		s.logger.Fatal().Err(err).Msg("an error occurred while hosting the mail server")
	}
}

func (s *Server) handler() error {
	ticker := time.NewTicker(s.interval * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:
			s.logger.Debug().Msg("Checking for mail")

			addresses, err := s.GetMail()
			if err != nil && err.Error() != "no new messages" {
				s.logger.Error().Err(err).Msg("could not obtain the latest mail from mail server")
			}

			var domainList []string
			for domain := range addresses {
				domainList = append(domainList, domain)
			}

			sourceDomainList := strings.NewReader(strings.Join(domainList, "\n"))
			source := scanner.TextSource(sourceDomainList)

			for result := range s.Scanner.Start(source) {
				sender := addresses[result.Domain].Address

				if addresses[result.Domain].DKIM != "" {
					result.DKIM = addresses[result.Domain].DKIM
				}

				if err = s.SendMail(sender, s.PrepareEmail(result)); err != nil {
					s.logger.Error().Err(err).Msg("An error occurred while sending scan results to " + sender)
					continue
				}

				s.logger.Info().Msg("Sent results to " + sender)
			}
		case <-quit:
			ticker.Stop()
			return errors.New("server manually stopped")
		}
	}
}
