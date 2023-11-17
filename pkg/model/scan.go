package model

import (
	"strings"

	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
	"github.com/spf13/cast"
)

type ScanResultWithAdvice struct {
	ScanResult *scanner.ScanResult `json:"scanResult" yaml:"scanResult"`
	Advice     map[string][]string `json:"advice,omitempty" yaml:"advice,omitempty"`
}

func (s *ScanResultWithAdvice) Csv() []string {
	var advice string
	for key, v := range s.Advice {
		for i, val := range v {
			v[i] = " " + key + ": " + val
		}

		advice += strings.Join(v, "; ")
	}

	return []string{s.ScanResult.Domain, strings.Join(s.ScanResult.A, "; "), strings.Join(s.ScanResult.AAAA, "; "), s.ScanResult.BIMI, s.ScanResult.CNAME, s.ScanResult.DKIM, s.ScanResult.DMARC, strings.Join(s.ScanResult.MX, "; "), s.ScanResult.SPF, strings.Join(s.ScanResult.TXT, "; "), cast.ToString(s.ScanResult.Elapsed), s.ScanResult.Error, advice}
}
