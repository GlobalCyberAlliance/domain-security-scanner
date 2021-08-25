package model

import "github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"

type ScanResultWithAdvice struct {
	*scanner.ScanResult
	Advice map[string][]string `json:"advice"`
}
