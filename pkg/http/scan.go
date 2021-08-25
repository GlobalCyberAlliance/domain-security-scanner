package http

import (
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/domainadvisor"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/model"
	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/gin-gonic/gin"
	"strings"
)

type bulkDomainRequest struct {
	Domains []string `json:"domains"`
}

func (s *Server) registerScanRoutes(r *gin.RouterGroup) {
	r.GET("/scan/:domain", s.handleScanDomain)
	r.POST("/scan", s.handleScanDomains)
}

func (s *Server) handleScanDomain(c *gin.Context) {
	domain := c.Param("domain")

	if queryParam, ok := c.GetQuery("dkimSelector"); ok {
		s.Scanner.DKIMSelector = queryParam
	}

	if queryParam, ok := c.GetQuery("recordType"); ok {
		s.Scanner.RecordType = queryParam
	}

	result := s.Scanner.Scan(domain)
	advice := domainadvisor.CheckAll(result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF)

	resultWithAdvice := model.ScanResultWithAdvice{
		ScanResult: result,
		Advice:     advice,
	}

	s.respond(c, 200, &resultWithAdvice)
}

func (s *Server) handleScanDomains(c *gin.Context) {
	var domains bulkDomainRequest

	if err := Decode(c, &domains); err != nil {
		s.logger.Error().Err(err).Msg("error occurred during handleScanDomains request")
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
		s.Scanner.DKIMSelector = queryParam
	}

	if queryParam, ok := c.GetQuery("recordType"); ok {
		s.Scanner.RecordType = queryParam
	}

	var resultsWithAdvice []model.ScanResultWithAdvice

	for result := range s.Scanner.Start(source) {
		advice := domainadvisor.CheckAll(result.DKIM, result.DMARC, result.Domain, result.MX, result.SPF)
		resultsWithAdvice = append(resultsWithAdvice, model.ScanResultWithAdvice{
			ScanResult: result,
			Advice:     advice,
		})
	}

	s.respond(c, 200, resultsWithAdvice)
}
