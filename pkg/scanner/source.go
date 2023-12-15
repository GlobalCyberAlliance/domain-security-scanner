package scanner

import (
	"bufio"
	"io"
	"strings"

	"github.com/miekg/dns"
)

const (
	TextSourceType SourceType = iota
	ZonefileSourceType
)

type (
	SourceType int

	// Source defines the interface of a data source that feeds a Scanner.
	Source interface {
		Read() <-chan string
		Close() error
	}

	source struct {
		ch         chan string
		closed     bool
		reader     io.Reader
		stop       chan struct{}
		sourceType SourceType
	}
)

func NewSource(reader io.Reader, sourceType SourceType) Source {
	return &source{reader: reader, sourceType: sourceType}
}

func (src *source) Read() <-chan string {
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

func (src *source) read() {
	defer close(src.ch)

	switch src.sourceType {
	case TextSourceType:
		sc := bufio.NewScanner(src.reader)
		for sc.Scan() {
			domain := strings.Trim(sc.Text(), ".")

			select {
			case src.ch <- domain:
			case <-src.stop:
				return
			}
		}
	case ZonefileSourceType:
		zoneParser := dns.NewZoneParser(src.reader, "", "")
		zoneParser.SetIncludeAllowed(true)

		for tok, ok := zoneParser.Next(); ok; tok, ok = zoneParser.Next() {
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
}

func (src *source) Close() error {
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
