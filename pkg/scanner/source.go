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
	return &zonefileSource{r: r}
}

type zonefileSource struct {
	r      io.Reader
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

	z := dns.NewZoneParser(src.r, "", "")
	z.SetIncludeAllowed(true)

	for tok, ok := z.Next(); ok; _, ok = z.Next() {
		if tok.Header().Rrtype == dns.TypeNS {
			continue
		}

		name := strings.Trim(tok.Header().Name, ".")
		if strings.Index(name, ".") == -1 {
			// We have an NS record that serves as an anchor, and
			// should skip it.
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

		// Drain the channel.
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
	return &textSource{r: r}
}

type textSource struct {
	r      io.Reader
	ch     chan string
	stop   chan struct{}
	closed bool
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
	sc := bufio.NewScanner(src.r)
	for sc.Scan() {
		name := strings.Trim(sc.Text(), ".")

		select {
		case src.ch <- name:
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
		for range src.ch {
		}
	}

	close(src.stop)
	src.closed = true
	return nil
}
