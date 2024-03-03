package mail

import (
	"fmt"
	htmlTmpl "html/template"
	textTmpl "text/template"
	"time"

	domainAdvisor "github.com/GlobalCyberAlliance/domain-security-scanner/pkg/advisor"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/model"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

type Server struct {
	advisor      *domainAdvisor.Advisor
	config       Config
	cooldown     *cache.Cache
	interval     time.Duration
	logger       zerolog.Logger
	templateHtml *htmlTmpl.Template
	templateText *textTmpl.Template
	CheckTls     bool
	Scanner      *scanner.Scanner
}

// NewMailServer returns a new instance of a mail server
func NewMailServer(config Config, logger zerolog.Logger, sc *scanner.Scanner, advisor *domainAdvisor.Advisor) (*Server, error) {
	s := Server{
		advisor:  advisor,
		config:   config,
		cooldown: cache.New(1*time.Minute, 5*time.Minute),
		logger:   logger,
		Scanner:  sc,
	}

	client, err := s.Login()
	if err != nil {
		return nil, err
	}
	defer client.Logout()

	if err = s.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize mail templates: %w", err)
	}

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
				if _, ok := s.cooldown.Get(domain); ok {
					continue
				}

				s.cooldown.Set(domain, "", 1*time.Minute)

				domainList = append(domainList, domain)
			}

			if len(domainList) == 0 {
				continue
			}

			results, err := s.Scanner.Scan(domainList...)
			if err != nil {
				s.logger.Error().Err(err).Msg("An error occurred while scanning domains")
				continue
			}

			for _, result := range results {
				sender := addresses[result.Domain].Address

				if addresses[result.Domain].DKIM != "" {
					result.DKIM = addresses[result.Domain].DKIM
				}

				resultWithAdvice := model.ScanResultWithAdvice{
					ScanResult: result,
				}

				if s.advisor != nil || result.Error == "" {
					resultWithAdvice.Advice = s.advisor.CheckAll(result.Domain, result.BIMI, result.DKIM, result.DMARC, result.MX, result.SPF)
				}

				if err = s.SendMail(sender, resultWithAdvice); err != nil {
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
