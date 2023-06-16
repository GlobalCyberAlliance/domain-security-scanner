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

const (
	DefaultBIMIPrefix  = "v=BIMI1;"
	DefaultDKIMPrefix  = "v=DKIM1;"
	DefaultDMARCPrefix = "v=DMARC1;"
	DefaultSPFPrefix   = "v=spf1 "
)

var (
	BIMIPrefix  = DefaultBIMIPrefix
	DKIMPrefix  = DefaultDKIMPrefix
	DMARCPrefix = DefaultDMARCPrefix
	SPFPrefix   = DefaultSPFPrefix
)

type (
	cachedResult struct {
		Expiry time.Time
		Result *ScanResult
	}

	// Scanner is a type that queries the DNS records for domain names, looking
	// for specific resource records.
	Scanner struct {
		// Cache is a simple in-memory cache to reduce external requests from
		// the scanner.
		Cache map[string]cachedResult

		// DKIMSelector is used to specify where a DKIM record is hosted for
		// a specific domain.
		DKIMSelector string

		// Nameservers is a slice of "host:port" strings of nameservers to
		// issue queries against.
		Nameservers []string

		// RecordType determines which queries are run against a provided
		// domain.
		RecordType string

		// cacheEnabled specifies whether the scanner should utilize the in-memory
		// cache or not.
		cacheEnabled bool

		// cacheMutex prevents concurrent map writes.
		cacheMutex *sync.Mutex

		// DNS client shared by all goroutines the scanner spawns.
		dc *dns.Client

		// The index of the last-used nameserver, from the Nameservers slice.
		//
		// This field is managed by atomic operations, and should only ever
		// be referenced by the (*Scanner).GetNS() method.
		nsidx uint32

		// A channel to use as a semaphore for limiting the number of DNS
		// queries that can be made concurrently.
		sem chan struct{}
	}

	// ScannerOption defines a functional configuration type for a *Scanner.
	ScannerOption func(*Scanner) error

	// ScanResult holds the results of scanning a domain's DNS records.
	ScanResult struct {
		Domain   string        `json:"domain" yaml:"domain,omitempty"`
		A        []string      `json:"a,omitempty" yaml:"a,omitempty"`
		AAAA     []string      `json:"aaaa,omitempty" yaml:"aaaa,omitempty"`
		BIMI     string        `json:"bimi,omitempty" yaml:"bimi,omitempty"`
		CNAME    string        `json:"cname,omitempty" yaml:"cname,omitempty"`
		DKIM     string        `json:"dkim,omitempty" yaml:"dkim,omitempty"`
		DMARC    string        `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
		MX       []string      `json:"mx,omitempty" yaml:"mx,omitempty"`
		SPF      string        `json:"spf,omitempty" yaml:"spf,omitempty"`
		TXT      []string      `json:"txt,omitempty" yaml:"txt,omitempty"`
		Duration time.Duration `json:"duration,omitempty" yaml:"duration,omitempty"`
		Err      error         `json:"-" yaml:"-"`
		Error    string        `json:"error,omitempty" yaml:"error,omitempty"`
	}
)

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

// UseCache enables domain caching for the scanner. This is a simple
// implementation, intended to mitigate abuse attempts.
func UseCache(enable bool) ScannerOption {
	return func(s *Scanner) error {
		if enable {
			s.Cache = make(map[string]cachedResult, 100)
			s.cacheEnabled = true
			s.cacheMutex = &sync.Mutex{}
		}
		return nil
	}
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

// UseNameservers allows the caller to provide a custom set of nameservers for
// a *Scanner to use. If ns is nil, or zero-length, the *Scanner will use
// the nameservers specified in /etc/resolv.conf.
func UseNameservers(ns []string) ScannerOption {
	return func(s *Scanner) error {
		// If the provided slice of nameservers is nil, or has zero
		// elements, load up /etc/resolv.conf, and get the "nameserver"
		// directives from there.
		if ns == nil || len(ns) == 0 {
			ns = []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}

			config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err == nil {
				ns = config.Servers[:]
			}
		}

		// Make sure each of the nameservers is in the "host:port"
		// format.
		//
		// The "dns" package requires that you explicitly state the port
		// number for the resolvers that get queried.
		for i := 0; i < len(ns); i++ {
			if host, port, err := net.SplitHostPort(ns[i]); err != nil {
				if strings.Count(ns[i], ":") > 2 && !strings.Contains(ns[i], "[") {
					ns[i] = "[" + ns[i] + "]" + ":53"
				} else {
					ns[i] = ns[i] + ":53"
				}
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

// Start consumes domain names from the Source src, scans the domain name's
// DNS records, and returns a channel of the results.
func (s *Scanner) Start(src Source) <-chan *ScanResult {
	results := make(chan *ScanResult)
	go s.start(src, results)
	return results
}

func (s *Scanner) start(src Source, ch chan *ScanResult) {
	defer close(ch)

	var wg sync.WaitGroup
	for dname := range src.Read() {
		<-s.sem
		wg.Add(1)
		go func(dname string) {
			ch <- s.Scan(dname)
			s.sem <- struct{}{}
			wg.Done()
		}(dname)
	}
	wg.Wait()
}

// Scan allows the caller to use the *Scanner's underlying data structures
// for performing a one-off scan of the given domain name.
func (s *Scanner) Scan(name string) *ScanResult {
	if s.cacheEnabled {
		if val, ok := s.Cache[name]; ok {
			if val.Expiry.Sub(time.Now()) < (time.Second * 60) {
				return val.Result
			}

			s.cacheMutex.Lock()
			delete(s.Cache, name)
			s.cacheMutex.Unlock()
		}
	}

	var err error
	res := &ScanResult{Domain: name}
	start := time.Now()

	switch s.RecordType {
	case "a":
		if res.A, err = s.getTypeA(res.Domain); err != nil {
			res.Err = errors.Wrap(err, "A")
		}
	case "aaaa":
		if res.A, err = s.getTypeAAAA(res.Domain); err != nil {
			res.Err = errors.Wrap(err, "AAAA")
		}
	case "all":
		if err = s.GetDNSRecords(res, "A", "AAAA", "BIMI", "CNAME", "DKIM", "DMARC", "MX", "SPF", "TXT"); err != nil {
			res.Err = errors.Wrap(err, "All")
		}
	case "cname":
		if res.CNAME, err = s.getTypeCNAME(res.Domain); err != nil {
			res.Err = errors.Wrap(err, "CNAME")
		}
	case "mx":
		if res.MX, err = s.getTypeMX(res.Domain); err != nil {
			res.Err = errors.Wrap(err, "MX")
		}
	case "txt":
		if res.TXT, err = s.getTypeTXT(res.Domain); err != nil {
			res.Err = errors.Wrap(err, "TXT")
		}
	default:
		// case "sec"
		if err = s.GetDNSRecords(res, "BIMI", "DKIM", "DMARC", "MX", "SPF"); err != nil {
			res.Err = errors.Wrap(err, "All")
		}
	}

	res.Duration = time.Since(start)
	if res.Err != nil {
		res.Error = res.Err.Error()
	}

	if s.cacheEnabled {
		s.cacheMutex.Lock()
		s.Cache[name] = cachedResult{
			Expiry: time.Now(),
			Result: res,
		}
		s.cacheMutex.Unlock()
	}

	return res
}

func (s *Scanner) GetNS() string {
	return s.Nameservers[int(atomic.AddUint32(&s.nsidx, 1))%len(s.Nameservers)]
}
