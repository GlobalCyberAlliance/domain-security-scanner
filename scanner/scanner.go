package scanner

/*
 * Copyright 2018 Global Cyber Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITION OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
	// IP addresses of publicly-available nameservers.
	GoogleDNS = []string{"8.8.8.8", "8.8.4.4"}
	Level3    = []string{"4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6"}
	OpenDNS   = []string{"208.67.222.222", "208.67.220.220"}
)

type ScanFlag uint

const (
	ScanDKIM ScanFlag = 1 << iota
	ScanDMARC
	ScanSPF
)

// ScannerOption defines a functional configuration type for a *Scanner.
type ScannerOption func(*Scanner) error

// UseNameservers allows the caller to provide a custom set of nameservers for
// a *Scanner to use. If ns is nil, or zero-length, the *Scanner will use
// the nameservers specified in /etc/resolv.conf.
func UseNameservers(ns []string) ScannerOption {
	return func(s *Scanner) error {
		// If the provided slice of nameservers is nil, or has a zero
		// elements, load up /etc/resolv.conf, and get the "nameserver"
		// directives from there.
		if ns == nil || len(ns) == 0 {
			config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				return errors.Wrap(err, "open /etc/resolv.conf")
			}
			ns = config.Servers[:]
		}

		// Make sure each of the nameservers is in the "host:port"
		// format.
		//
		// The "dns" package requires that you explicitly state the port
		// number for the resolvers that get queried.
		for i := 0; i < len(ns); i++ {
			if host, port, err := net.SplitHostPort(ns[i]); err != nil {
				ns[i] = ns[i] + ":53"
			} else if port == "" {
				ns[i] = net.JoinHostPort(host, "53")
			}
		}
		s.Nameservers = ns[:]
		return nil
	}
}

// WithTimeout sets the timeout duration of a DNS query.
func WithTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) error {
		s.dc.Timeout = timeout
		return nil
	}
}

// ConcurrentScans sets the number of domains that will be scanned
// concurrently.
//
// If n <= 0, then this option will default to the return value of
// runtime.NumCPU().
func ConcurrentScans(n int) ScannerOption {
	return func(s *Scanner) error {
		if n <= 0 {
			n = runtime.NumCPU()
		}
		if s.sem != nil {
			close(s.sem)
		}
		s.sem = make(chan struct{}, n)
		return nil
	}
}

// Scanner is a type that queries the DNS records for domain names, looking
// for specific resource records.
type Scanner struct {
	// Nameservers is a slice of "host:port" strings of nameservers to
	// issue queries against.
	Nameservers []string

	// The index of the last-used nameserver, from the Nameservers slice.
	//
	// This field is managed by atomic operations, and should only ever
	// be referenced by the (*Scanner).getNS() method.
	nsidx uint32

	// DNS client shared by all goroutines the scanner spawns.
	dc *dns.Client

	// A channel to use as a semaphore for limiting the number of DNS
	// queries that can be made concurrently.
	sem chan struct{}
}

// New initializes and returns a new *Scanner.
func New(options ...ScannerOption) (*Scanner, error) {
	s := &Scanner{
		dc: new(dns.Client),
	}

	for _, option := range options {
		if err := option(s); err != nil {
			return nil, errors.Wrap(err, "apply option")
		}
	}

	if s.sem == nil {
		s.sem = make(chan struct{}, runtime.NumCPU())
	}
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}

	s.dc.SingleInflight = true

	return s, nil
}

// ScanResult holds the results of scanning a domain's DNS records.
type ScanResult struct {
	Domain   string        `json:"domain"`
	SPF      string        `json:"spf"`
	DMARC    string        `json:"dmarc"`
	DKIM     string        `json:"-"`
	Duration time.Duration `json:"duration"`
	Err      error         `json:"-"`
	Error    string        `json:"error,omitempty"`
}

// Start consumes domain names from the Source src, scans the domain name's
// DNS records, and returns a channel of the results.
func (sc *Scanner) Start(src Source) <-chan *ScanResult {
	results := make(chan *ScanResult)
	go sc.start(src, results)
	return results
}

func (sc *Scanner) start(src Source, ch chan *ScanResult) {
	defer close(ch)

	var wg sync.WaitGroup
	for dname := range src.Read() {
		<-sc.sem
		wg.Add(1)
		go func(dname string) {
			ch <- sc.scan(dname)
			sc.sem <- struct{}{}
			wg.Done()
		}(dname)
	}
	wg.Wait()
}

// Scan allows the caller to use the *Scanner's underlying data structures
// for performing a one-off scan of the given domain name.
func (sc *Scanner) Scan(name string) *ScanResult {
	return sc.scan(name)
}

func (sc *Scanner) scan(name string) *ScanResult {
	res := &ScanResult{Domain: name}
	start := time.Now()

	if v, err := sc.spf(name); err != nil {
		res.Err = errors.Wrap(err, "spf")
	} else {
		res.SPF = v
	}

	if v, err := sc.dmarc(name); err != nil {
		res.Err = errors.Wrap(err, "dmarc")
	} else {
		res.DMARC = v
	}

	res.Duration = time.Since(start)
	if res.Err != nil {
		res.Error = res.Err.Error()
	}
	return res
}

func (s *Scanner) spf(name string) (string, error) {
	req := newTXTRequest(name)
	in, _, err := s.dc.Exchange(req, s.getNS())
	if err != nil {
		return "", errors.Wrap(err, "exchange")
	}

	for _, ans := range in.Answer {
		t, ok := ans.(*dns.TXT)
		if !ok {
			continue
		}
		for _, txt := range t.Txt {
			if strings.HasPrefix(txt, spfPrefix) {
				return txt, nil
			}
		}
	}

	return "", nil
}

func (s *Scanner) dmarc(name string) (string, error) {
	for _, dname := range []string{
		"_dmarc." + name,
		name,
	} {
		req := newTXTRequest(dname)
		in, _, err := s.dc.Exchange(req, s.getNS())
		if err != nil {
			return "", errors.Wrap(err, "exchange")
		}

		for _, ans := range in.Answer {
			t, ok := ans.(*dns.TXT)
			if !ok {
				continue
			}
			for _, txt := range t.Txt {
				if strings.HasPrefix(txt, dmarcPrefix) {
					return txt, nil
				}
			}
		}
	}
	return "", nil
}

const (
	spfPrefix   = "v=spf1 "
	dmarcPrefix = "v=DMARC1;"
)

func (s *Scanner) getNS() string {
	return s.Nameservers[int(atomic.AddUint32(&s.nsidx, 1))%len(s.Nameservers)]
}

func newTXTRequest(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	return m
}
