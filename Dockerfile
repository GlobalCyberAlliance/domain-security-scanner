FROM golang:1.20.5-alpine3.18 AS builder

RUN apk add git make

COPY . /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

WORKDIR /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

RUN make

FROM scratch

COPY --from=builder /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/bin/dss /dss
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/dss" ]
