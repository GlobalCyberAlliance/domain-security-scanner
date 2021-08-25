PROJECT			:= github.com/GlobalCyberAlliance/DomainSecurityScanner
GO				:= $(shell which go 2>/dev/null)
GOFMT			:= $(shell which gofmt 2>/dev/null)
GO_BENCH_FLAGS	:= -short -bench=. -benchmem
GO_BENCH		:= $(GO) test $(GO_BENCH_FLAGS)
GO_BUILD_FLAGS	:= -ldflags "-s -w"
GO_BUILD		:= $(GO) build $(GO_BUILD_FLAGS)
GO_FORMAT_FLAGS	:= -s -w
GO_FORMAT		:= $(GOFMT) $(GO_FORMAT_FLAGS)
GO_TEST_FLAGS	:= -v -short
GO_TEST			:= $(GO) test $(GO_TEST_FLAGS)
GO_TIDY			:= $(GO) mod tidy
TARGETS			:= bin/dss

all: format clean bin $(TARGETS)

bin:
	mkdir -p $@

bin/%: $(shell find . -name "*.go" -type f)
ifeq ("${GO}","")
	$(error Cannot find "go" in your $$PATH)
endif
	$(GO_TIDY)
	CGO_ENABLED=0 $(GO_BUILD) -o $@ $(PROJECT)/cmd/$*

clean:
	-rm -rf bin

format:
ifeq ("${GOFMT}","")
	$(error Cannot find "gofmt" in your $$PATH)
endif
	$(GO_FORMAT) $(PWD)