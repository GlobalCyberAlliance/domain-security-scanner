FROM golang:1.19.0-alpine3.16 AS builder

RUN apk add git make

COPY . /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

WORKDIR /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

RUN make

FROM scratch

COPY --from=builder /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/bin/dss /dss
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/dss" ]
