package main

import (
	"github.com/GlobalCyberAlliance/GCADMARCRiskScanner/cmd"
	_ "github.com/GlobalCyberAlliance/GCADMARCRiskScanner/cmd/bulk"
	_ "github.com/GlobalCyberAlliance/GCADMARCRiskScanner/cmd/single"
)

func main() {
	_ = cmd.Root.Execute()
}
