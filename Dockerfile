FROM golang:1.14.4-alpine3.12 AS builder

RUN apk add git

COPY . /go/src/github.com/GlobalCyberAlliance/GCADMARCRiskScanner/

WORKDIR /go/src/github.com/GlobalCyberAlliance/GCADMARCRiskScanner/

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o drs

FROM scratch

COPY --from=builder /go/src/github.com/GlobalCyberAlliance/GCADMARCRiskScanner/drs /drs

ENTRYPOINT [ "/drs" ]