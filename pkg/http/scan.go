package http

import (
	"strings"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domain_advisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/model"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/gin-gonic/gin"
)

type bulkDomainRequest struct {
	Domains []string `json:"domains"`
}

func (s *Server) registerScanRoutes(r *gin.RouterGroup) {
	r.GET("/scan/:domain", s.handleScanDomains)
	r.POST("/scan", s.handleScanDomains)
}

func (s *Server) handleScanDomains(c *gin.Context) {
	var domains bulkDomainRequest

	switch c.Request.Method {
	case "GET":
		domains.Domains = []string{c.Param("domain")}
		break
	case "POST":
		if err := Decode(c, &domains); err != nil {
			s.logger.Error().Err(err).Msg("error occurred during handleScanDomains request")
			s.respond(c, 400, "you need to supply an array of domains in the body of the request, formatted as json")
			return
		}
		break
	default:
		s.respond(c, 405, "method not allowed")
		return
	}

	// check for empty array
	if len(domains.Domains) == 0 {
		s.respond(c, 400, "you need to supply an array of domains in the body of the request, formatted as json")
		return
	}

	// mitigate potential abuse
	if len(domains.Domains) > 20 {
		s.respond(c, 400, "you cannot bulk process more than 20 domains at a time")
		return
	}

	domainList := strings.NewReader(strings.Join(domains.Domains, "\n"))
	source := scanner.TextSource(domainList)

	if queryParam, ok := c.GetQuery("dkimSelector"); ok {
		s.Scanner.DKIMSelectors = strings.Split(queryParam, ",")
	}

	var resultsWithAdvice []model.ScanResultWithAdvice

	for result := range s.Scanner.Start(source) {
		resultsWithAdvice = append(resultsWithAdvice, model.ScanResultWithAdvice{
			ScanResult: result,
			Advice:     domainAdvisor.CheckAll(result.BIMI, result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF, s.CheckTls),
		})
	}

	if len(resultsWithAdvice) == 0 {
		s.respond(c, 404, "no results found")
		return
	}

	switch c.Request.Method {
	case "GET":
		s.respond(c, 200, resultsWithAdvice[0])
	case "POST":
		s.respond(c, 200, resultsWithAdvice)
	}
}
