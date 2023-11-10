FROM golang:1.21-alpine3.18 AS build

RUN apk add git make \
 && go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest

COPY . /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

WORKDIR /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/

RUN make

FROM scratch

COPY --from=build /go/src/github.com/GlobalCyberAlliance/DomainSecurityScanner/bin/dss /dss
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/dss" ]