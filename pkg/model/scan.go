package model

import "github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"

type ScanResultWithAdvice struct {
	ScanResult *scanner.ScanResult `json:"scanResult" yaml:"scanResult"`
	Advice     map[string][]string `json:"advice" yaml:"advice"`
}
