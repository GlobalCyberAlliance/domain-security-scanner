package scanner

import (
	"bufio"
	"io"
	"strings"

	"github.com/miekg/dns"
)

// Source defines the interface of a data source that feeds a Scanner.
type Source interface {
	Read() <-chan string
	Close() error
}

// ZonefileSource returns a Source that can be used by a Scanner to read
// domain names from an io.Reader that reads from a RFC 1035 formatted zone
// file.
func ZonefileSource(r io.Reader) Source {
	return &zonefileSource{reader: r}
}

type zonefileSource struct {
	reader io.Reader
	ch     chan string
	stop   chan struct{}
	closed bool
}

func (src *zonefileSource) Read() <-chan string {
	if src.closed {
		return nil
	}

	if src.ch != nil {
		return src.ch
	}

	src.ch = make(chan string)

	if src.stop == nil {
		src.stop = make(chan struct{})
	}

	go src.read()

	return src.ch
}

func (src *zonefileSource) read() {
	defer close(src.ch)

	zoneParser := dns.NewZoneParser(src.reader, "", "")
	zoneParser.SetIncludeAllowed(true)

	for tok, ok := zoneParser.Next(); ok; _, ok = zoneParser.Next() {
		if tok.Header().Rrtype == dns.TypeNS {
			continue
		}

		name := strings.Trim(tok.Header().Name, ".")
		if !strings.Contains(name, ".") {
			// we have an NS record that serves as an anchor, and should skip it
			continue
		}

		select {
		case src.ch <- name:
		case <-src.stop:
			return
		}
	}
}

func (src *zonefileSource) Close() error {
	if src.closed {
		return nil
	}
	if len(src.ch) > 0 {
		src.stop <- struct{}{}

		// drain the channel
		for range src.ch {
		}
	}
	close(src.ch)
	close(src.stop)
	src.closed = true
	return nil
}

// TextSource returns a new Source that can be used by a Scanner to read
// newline-separated domain names from r.
func TextSource(r io.Reader) Source {
	return &textSource{reader: r}
}

type textSource struct {
	ch     chan string
	closed bool
	reader io.Reader
	stop   chan struct{}
}

func (src *textSource) Read() <-chan string {
	if src.closed {
		return nil
	}

	if src.ch != nil {
		return src.ch
	}

	src.ch = make(chan string)
	src.stop = make(chan struct{})

	go src.read()

	return src.ch
}

func (src *textSource) read() {
	defer close(src.ch)

	sc := bufio.NewScanner(src.reader)
	for sc.Scan() {
		domain := strings.Trim(sc.Text(), ".")

		select {
		case src.ch <- domain:
		case <-src.stop:
			return
		}
	}
}

func (src *textSource) Close() error {
	if src.closed {
		return nil
	}

	if len(src.ch) > 0 {
		src.stop <- struct{}{}

		// drain the channel
		for range src.ch {
		}
	}

	close(src.stop)
	src.closed = true
	return nil
}
