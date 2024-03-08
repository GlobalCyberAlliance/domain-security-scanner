package scanner

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

type (
	Scanner struct {
		// cache is a simple in-memory cache to reduce external requests from the scanner.
		cache *cache.Cache

		// cacheDuration is the time-to-live for cache entries.
		cacheDuration time.Duration

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

		// logger is the logger for the scanner.
		logger zerolog.Logger

		// nameservers is a slice of "host:port" strings of nameservers to issue queries against.
		nameservers []string

		// pool is the pool of workers for the scanner.
		pool *ants.Pool

		// poolSize is the size of the pool of workers for the scanner.
		poolSize uint16
	}

	// Option defines a functional configuration type for a *Scanner.
	Option func(*Scanner) error

	// Result holds the results of scanning a domain's DNS records.
	Result struct {
		Domain string   `json:"domain" yaml:"domain,omitempty" doc:"The domain name being scanned." example:"example.com"`
		Error  string   `json:"error,omitempty" yaml:"error,omitempty" doc:"An error message if the scan failed." example:"invalid domain name"`
		BIMI   string   `json:"bimi,omitempty" yaml:"bimi,omitempty" doc:"The BIMI record for the domain." example:"https://example.com/bimi.svg"`
		DKIM   string   `json:"dkim,omitempty" yaml:"dkim,omitempty" doc:"The DKIM record for the domain." example:"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"`
		DMARC  string   `json:"dmarc,omitempty" yaml:"dmarc,omitempty" doc:"The DMARC record for the domain." example:"v=DMARC1; p=none"`
		MX     []string `json:"mx,omitempty" yaml:"mx,omitempty" doc:"The MX records for the domain." example:"aspmx.l.google.com"`
		NS     []string `json:"ns,omitempty" yaml:"ns,omitempty" doc:"The NS records for the domain." example:"ns1.example.com"`
		SPF    string   `json:"spf,omitempty" yaml:"spf,omitempty" doc:"The SPF record for the domain."example:"v=spf1 include:_spf.google.com ~all"`
	}
)

func New(logger zerolog.Logger, timeout time.Duration, opts ...Option) (*Scanner, error) {
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than 0")
	}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	dnsClient.Timeout = timeout

	scanner := &Scanner{
		dnsClient:   dnsClient, // Initialize a new dns.Client
		dnsBuffer:   4096,      // Set the dnsBuffer size to 1024 bytes
		logger:      logger,
		nameservers: []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}, // Set the default nameservers to Google and Cloudflare
		poolSize:    uint16(runtime.NumCPU()),
	}

	for _, opt := range opts {
		if err := opt(scanner); err != nil {
			return nil, errors.Wrap(err, "apply option")
		}
	}

	// Initialize cache
	scanner.cache = cache.New(scanner.cacheDuration, 5*time.Minute)

	// Create a new pool of workers for the scanner
	pool, err := ants.NewPool(int(scanner.poolSize), ants.WithExpiryDuration(timeout), ants.WithPanicHandler(func(err interface{}) {
		scanner.logger.Error().Err(errors.New(cast.ToString(err))).Msg("unrecoverable panic occurred while analysing pcap")
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner pool: %w", err)
	}

	scanner.pool = pool

	return scanner, nil
}

// Scan scans a list of domains and returns the results.
func (s *Scanner) Scan(domains ...string) ([]*Result, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("scanner is closed")
	}

	for _, domain := range domains {
		if domain == "" {
			return nil, errors.New("empty domain")
		}
	}

	if len(domains) == 0 {
		return nil, errors.New("no domains to scan")
	}

	var mutex sync.Mutex
	var results []*Result
	var wg sync.WaitGroup

	for _, domainToScan := range domains {
		wg.Add(1)

		if err := s.pool.Submit(func() {
			defer func() {
				wg.Done()
			}()

			var err error
			result := &Result{
				Domain: domainToScan,
			}

			if s.cache != nil {
				if scanResult, ok := s.cache.Get(domainToScan); ok {
					s.logger.Debug().Msg("cache hit for " + domainToScan)

					mutex.Lock()
					results = append(results, scanResult.(*Result))
					mutex.Unlock()

					return
				}

				s.logger.Debug().Msg("cache miss for " + domainToScan)

				defer func() {
					s.logger.Debug().Msg("filling cache for " + domainToScan)
					s.cache.Set(domainToScan, result, 3*time.Minute)
				}()
			}

			// check that the domain name is valid
			result.NS, err = s.getDNSRecords(domainToScan, dns.TypeNS)
			if err != nil || len(result.NS) == 0 {
				// check if TXT records exist, as the nameserver check won't work for subdomains
				records, err := s.getDNSAnswers(domainToScan, dns.TypeTXT)
				if err != nil || len(records) == 0 {
					// fill variable to satisfy deferred cache fill
					result = &Result{
						Domain: domainToScan,
						Error:  "invalid domain name",
					}

					mutex.Lock()
					results = append(results, result)
					mutex.Unlock()

					return
				}
			}

			scanWg := sync.WaitGroup{}
			scanWg.Add(5)

			// Get BIMI record
			go func() {
				defer scanWg.Done()
				result.BIMI, err = s.getTypeBIMI(domainToScan)
			}()

			// Get DKIM record
			go func() {
				defer scanWg.Done()
				result.DKIM, err = s.getTypeDKIM(domainToScan)
			}()

			// Get DMARC record
			go func() {
				defer scanWg.Done()
				result.DMARC, err = s.getTypeDMARC(domainToScan)
			}()

			// Get MX records
			go func() {
				defer scanWg.Done()
				result.MX, err = s.getDNSRecords(domainToScan, dns.TypeMX)
			}()

			// Get SPF record
			go func() {
				defer scanWg.Done()
				result.SPF, err = s.getTypeSPF(domainToScan)
			}()

			scanWg.Wait()

			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}); err != nil {
			return nil, err
		}
	}

	wg.Wait()

	return results, nil
}

func (s *Scanner) ScanZone(zone io.Reader) ([]*Result, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("scanner is closed")
	}

	zoneParser := dns.NewZoneParser(zone, "", "")
	zoneParser.SetIncludeAllowed(true)

	var domains []string

	for tok, ok := zoneParser.Next(); ok; tok, ok = zoneParser.Next() {
		if tok.Header().Rrtype == dns.TypeNS {
			continue
		}

		domain := strings.Trim(tok.Header().Name, ".")
		if !strings.Contains(domain, ".") {
			// we have an NS record that serves as an anchor, and should skip it
			continue
		}

		domains = append(domains, domain)
	}

	return s.Scan(domains...)
}

// Close closes the scanner
func (s *Scanner) Close() {
	s.pool.Release()
	s.cache.Flush()
	s.logger.Debug().Msg("scanner closed")
}

func (s *Scanner) getNS() string {
	return s.nameservers[int(atomic.AddUint32(&s.lastNameserverIndex, 1))%len(s.nameservers)]
}
