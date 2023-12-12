package advisor

import (
	"reflect"
	"testing"
	"time"
)

func TestAdvisor_CheckDMARC(t *testing.T) {
	advisor := NewAdvisor(time.Second)

	t.Run("missing", func(t *testing.T) {
		expectedAdvice := []string{
			"You do not have DMARC setup!",
		}

		advice := advisor.CheckDMARC("")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		expectedAdvice := []string{
			"Your DMARC record appears to be malformed as no semicolons seem to be present.",
		}

		advice := advisor.CheckDMARC("v=DMARC1 fo=1")

		if !reflect.DeepEqual(advice, expectedAdvice) {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("first_tag", func(t *testing.T) {
		expectedAdvice := "The beginning of your DMARC record should be v=DMARC1 with specific capitalization."
		advice := advisor.CheckDMARC("v=dmarc1;")

		if advice[0] != expectedAdvice {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice)
		}
	})

	t.Run("second_tag", func(t *testing.T) {
		expectedAdvice := "The second tag in your DMARC record must be p=none/p=quarantine/p=reject."
		advice := advisor.CheckDMARC("v=DMARC1; fo=1; p=reject;")

		if advice[0] != expectedAdvice {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice)
		}
	})

	t.Run("invalid_failure_option", func(t *testing.T) {
		expectedAdvice := "Invalid failure options specified, the record must be fo=0/fo=1/fo=d/fo=s."
		advice := advisor.CheckDMARC("v=DMARC1; p=random; fo=random;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_percentage", func(t *testing.T) {
		expectedAdvice := "Invalid report percentage specified, it must be between 0 and 100."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; pct=101;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_policy", func(t *testing.T) {
		expectedAdvice := "Invalid DMARC policy specified, the record must be p=none/p=quarantine/p=reject."
		advice := advisor.CheckDMARC("v=DMARC1; p=random; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_report_interval_type", func(t *testing.T) {
		expectedAdvice := "Invalid report interval specified, it must be a positive integer."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; ri=one;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_report_interval_value", func(t *testing.T) {
		expectedAdvice := "Invalid report interval specified, it must be a positive value."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; ri=-1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_rua_destination_address", func(t *testing.T) {
		expectedAdvice := "Invalid aggregate report destination specified, it should be a valid email address."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; rua=mailto:dest")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_rua_destination_format", func(t *testing.T) {
		expectedAdvice := "Invalid aggregate report destination specified, it should begin with mailto:."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; rua=dest@domain.tld")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_ruf_destination_address", func(t *testing.T) {
		expectedAdvice := "Invalid forensic report destination specified, it should be a valid email address."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; ruf=mailto:dest")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_ruf_destination_format", func(t *testing.T) {
		expectedAdvice := "Invalid forensic report destination specified, it should begin with mailto:."
		advice := advisor.CheckDMARC("v=DMARC1; p=none; fo=1; ruf=dest@domain.tld")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("invalid_subdomain_policy", func(t *testing.T) {
		expectedAdvice := "Invalid subdomain policy specified, the record must be sp=none/sp=quarantine/sp=reject."
		advice := advisor.CheckDMARC("v=DMARC1; sp=random; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice, expectedAdvice)
		}
	})

	t.Run("missing_subdomain_policy", func(t *testing.T) {
		expectedAdvice := "Subdomain policy isn't specified, they'll default to the main policy instead."
		advice := advisor.CheckDMARC("v=DMARC1; p=reject; fo=1;")
		found := false

		for _, a := range advice {
			if a == expectedAdvice {
				found = true
			}
		}

		if !found {
			t.Errorf("found %v, want %v", advice[0], expectedAdvice[0])
		}
	})
}
