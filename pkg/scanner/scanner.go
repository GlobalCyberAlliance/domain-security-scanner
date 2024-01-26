package scanner

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
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

	// knownDkimSelectors is a list of known DKIM selectors.
	knownDkimSelectors = []string{
		"x",             // Generic
		"google",        // Google
		"selector1",     // Microsoft
		"selector2",     // Microsoft
		"k1",            // MailChimp
		"mandrill",      // Mandrill
		"everlytickey1", // Everlytic
		"everlytickey2", // Everlytic
		"dkim",          // Hetzner
		"mxvault",       // MxVault
	}
)

type (
	// Scanner is a type that queries the DNS records for domain names, looking
	// for specific resource records.
	Scanner struct {
		// cache is a simple in-memory cache to reduce external requests from he scanner.
		cache *cache.Cache

		// cacheEnabled specifies whether the scanner should utilize the in-memory cache or not.
		cacheEnabled bool

		// dkimSelectors is used to specify where a DKIM record is hosted for a specific domain.
		dkimSelectors []string

		// DNS client shared by all goroutines the scanner spawns.
		dnsClient *dns.Client

		// dnsBuffer is used to configure the size of the buffer allocated for DNS responses.
		dnsBuffer uint16

		// The index of the last-used nameserver, from the nameservers slice.
		//
		// This field is managed by atomic operations, and should only ever be referenced by the (*Scanner).getNS()
		// method.
		lastNameserverIndex uint32

		// nameservers is a slice of "host:port" strings of nameservers to issue queries against.
		nameservers []string

		// A channel to use as a semaphore for limiting the number of DNS queries that can be made concurrently.
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

// New is a function that initializes and returns a new instance of the Scanner struct.
// It accepts a variadic number of ScannerOption functions that can be used to configure the Scanner instance.
func New(options ...ScannerOption) (*Scanner, error) {
	// Create a new Scanner instance with some default values
	s := &Scanner{
		dnsClient:   new(dns.Client),                                    // Initialize a new dns.Client
		dnsBuffer:   1024,                                               // Set the dnsBuffer size to 1024 bytes
		nameservers: []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}, // Set the default nameservers to Google and Cloudflare
	}

	// Apply each of the provided options to the Scanner instance.
	// If any of the options return an error, wrap the error with additional context and return it immediately.
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, errors.Wrap(err, "apply option")
		}
	}

	// If no semaphore channel (s.sem) has been set by the options, create a new one with a capacity equal to the number of CPU cores available
	if s.sem == nil {
		s.sem = make(chan struct{}, runtime.NumCPU())
	}

	// Fill the semaphore channel with empty struct{} instances
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}

	// Return the configured Scanner instance
	return s, nil
}

// OverwriteOption allows the caller to overwrite an existing option.
func (s *Scanner) OverwriteOption(option ScannerOption) error {
	return option(s)
}

// WithCache enables domain caching for the scanner. This is a simple
// implementation, intended to mitigate abuse attempts.
func WithCache(enable bool) ScannerOption {
	return func(s *Scanner) error {
		if enable {
			s.cache = cache.New(1*time.Minute, 5*time.Minute)
			s.cacheEnabled = true
		}
		return nil
	}
}

// WithConcurrentScans sets the number of domains that will be scanned
// concurrently.
//
// If n <= 0, then this option will default to the return value of
// runtime.NumCPU().
func WithConcurrentScans(n int) ScannerOption {
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

// WithDKIMSelectors allows the caller to specify which DKIM selectors to
// scan for (falling back to the default selectors if none are provided).
func WithDKIMSelectors(selectors ...string) ScannerOption {
	return func(s *Scanner) error {
		s.dkimSelectors = selectors
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

// WithNameservers allows the caller to provide a custom set of nameservers for
// a *Scanner to use. If ns is nil, or zero-length, the *Scanner will use
// the nameservers specified in /etc/resolv.conf.
func WithNameservers(ns []string) ScannerOption {
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

		s.nameservers = ns[:]

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
		go func(domain string) {
			ch <- s.Scan(domain)
			s.sem <- struct{}{}
			wg.Done()
		}(domain)
	}

	wg.Wait()
}

// Scan allows the caller to use the *Scanner's underlying data structures
// for performing a one-off scan of the given domain name.
func (s *Scanner) Scan(domain string) (result *ScanResult) {
	if s.cacheEnabled {
		if scanResult, ok := s.cache.Get(domain); ok {
			return scanResult.(*ScanResult)
		}

		defer func() {
			s.cache.Set(domain, result, 3*time.Minute)
		}()
	}

	// check that the domain name is valid
	records, err := s.getDNSAnswers(domain, dns.TypeNS)
	if err != nil || len(records) == 0 {
		// check if TXT records exist, as the nameserver check won't work for subdomains
		records, err = s.getDNSAnswers(domain, dns.TypeTXT)
		if err != nil || len(records) == 0 {
			// fill variable to satisfy deferred cache fill
			result = &ScanResult{
				Domain: domain,
				Error:  "invalid domain name",
			}

			return result
		}
	}

	result = &ScanResult{Domain: domain}
	start := time.Now()

	if err = s.GetDNSRecords(result, "BIMI", "DKIM", "DMARC", "MX", "NS", "SPF"); err != nil {
		result.Error = err.Error()
	}

	result.Elapsed = time.Since(start).Milliseconds()

	return result
}

func (s *Scanner) getNS() string {
	return s.nameservers[int(atomic.AddUint32(&s.lastNameserverIndex, 1))%len(s.nameservers)]
}
