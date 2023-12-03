package scanner

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

		// DKIMSelectors is used to specify where a DKIM record is hosted for
		// a specific domain.
		DKIMSelectors []string

		// Nameservers is a slice of "host:port" strings of nameservers to
		// issue queries against.
		Nameservers []string

		// cacheEnabled specifies whether the scanner should utilize the in-memory
		// cache or not.
		cacheEnabled bool

		// cacheMutex prevents concurrent map writes
		cacheMutex *sync.Mutex

		// DNS client shared by all goroutines the scanner spawns.
		dnsClient *dns.Client

		// dnsBuffer is used to configure the size of the buffer allocated for
		// DNS responses
		dnsBuffer uint16

		// The index of the last-used nameserver, from the Nameservers slice.
		//
		// This field is managed by atomic operations, and should only ever
		// be referenced by the (*Scanner).GetNS() method.
		lastNameserverIndex uint32

		// A channel to use as a semaphore for limiting the number of DNS
		// queries that can be made concurrently.
		sem chan struct{}
	}

	// ScannerOption defines a functional configuration type for a *Scanner.
	ScannerOption func(*Scanner) error

	// ScanResult holds the results of scanning a domain's DNS records.
	ScanResult struct {
		Domain  string   `json:"domain" yaml:"domain,omitempty"`
		Elapsed int64    `json:"elapsed,omitempty" yaml:"elapsed,omitempty"`
		Error   string   `json:"error,omitempty" yaml:"error,omitempty"`
		A       []string `json:"a,omitempty" yaml:"a,omitempty"`
		AAAA    []string `json:"aaaa,omitempty" yaml:"aaaa,omitempty"`
		BIMI    string   `json:"bimi,omitempty" yaml:"bimi,omitempty"`
		CNAME   string   `json:"cname,omitempty" yaml:"cname,omitempty"`
		DKIM    string   `json:"dkim,omitempty" yaml:"dkim,omitempty"`
		DMARC   string   `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
		MX      []string `json:"mx,omitempty" yaml:"mx,omitempty"`
		NS      []string `json:"ns,omitempty" yaml:"ns,omitempty"`
		SPF     string   `json:"spf,omitempty" yaml:"spf,omitempty"`
		TXT     []string `json:"txt,omitempty" yaml:"txt,omitempty"`
	}
)

// New initializes and returns a new *Scanner.
func New(options ...ScannerOption) (*Scanner, error) {
	s := &Scanner{
		dnsClient: new(dns.Client),
		dnsBuffer: 1024,
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

	return s, nil
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

// UseNameservers allows the caller to provide a custom set of nameservers for
// a *Scanner to use. If ns is nil, or zero-length, the *Scanner will use
// the nameservers specified in /etc/resolv.conf.
func UseNameservers(ns []string) ScannerOption {
	return func(s *Scanner) error {
		// If the provided slice of nameservers is nil, or has zero
		// elements, load up /etc/resolv.conf, and get the "nameserver"
		// directives from there.
		if len(ns) == 0 {
			ns = []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}

			config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err == nil {
				ns = config.Servers[:]
			}
		}

		// Make sure each of the nameservers is in the "host:port" format.
		//
		// The "dns" package requires that you explicitly state the port
		// number for the resolvers that get queried.
		for i := range ns {
			host, port, err := net.SplitHostPort(ns[i])
			if err != nil {
				// no port is specified
				if strings.Count(ns[i], ":") > 2 && !strings.Contains(ns[i], "[") {
					// handle IPv6 addresses without brackets
					ns[i] = "[" + ns[i] + "]:53"
				} else {
					// handle regular addresses or IPv6 with brackets
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

// WithDNSBuffer increases the allocated buffer for DNS responses
func WithDNSBuffer(bufferSize uint16) ScannerOption {
	return func(s *Scanner) error {
		if bufferSize > 4096 {
			return errors.New("buffer size should not be larger than 4096")
		}

		s.dnsBuffer = bufferSize
		return nil
	}
}

// WithTimeout sets the timeout duration of a DNS query.
func WithTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) error {
		s.dnsClient.Timeout = timeout
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
	for domain := range src.Read() {
		<-s.sem
		wg.Add(1)
		go func(dname string) {
			ch <- s.Scan(dname)
			s.sem <- struct{}{}
			wg.Done()
		}(domain)
	}

	wg.Wait()
}

// Scan allows the caller to use the *Scanner's underlying data structures
// for performing a one-off scan of the given domain name.
func (s *Scanner) Scan(domain string) *ScanResult {
	if s.cacheEnabled {
		s.cacheMutex.Lock()
		if val, ok := s.Cache[domain]; ok {
			if time.Now().Before(val.Expiry) {
				s.cacheMutex.Unlock()
				return val.Result
			}

			delete(s.Cache, domain)
		}
		s.cacheMutex.Unlock()
	}

	// check that the domain name is valid
	if _, err := net.LookupHost(domain); err != nil {
		return &ScanResult{
			Domain: domain,
			Error:  "invalid domain name",
		}
	}

	res := &ScanResult{Domain: domain}
	start := time.Now()

	if err := s.GetDNSRecords(res, "BIMI", "DKIM", "DMARC", "MX", "NS", "SPF"); err != nil {
		res.Error = err.Error()
	}

	res.Elapsed = time.Since(start).Milliseconds()

	if s.cacheEnabled {
		s.cacheMutex.Lock()
		s.Cache[domain] = cachedResult{
			Expiry: time.Now().Add(time.Minute),
			Result: res,
		}
		s.cacheMutex.Unlock()
	}

	return res
}

func (s *Scanner) GetNS() string {
	return s.Nameservers[int(atomic.AddUint32(&s.lastNameserverIndex, 1))%len(s.Nameservers)]
}
