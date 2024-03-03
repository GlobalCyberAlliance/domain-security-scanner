FROM golang:1.22-alpine3.19 AS build

RUN apk add git make \
 && apk cache clean \
 && go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest

COPY . /go/src/github.com/GlobalCyberAlliance/domain-security-scanner/

WORKDIR /go/src/github.com/GlobalCyberAlliance/domain-security-scanner/

RUN make

FROM scratch

COPY --from=build /go/src/github.com/GlobalCyberAlliance/domain-security-scanner/bin/dss /dss
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/dss" ]