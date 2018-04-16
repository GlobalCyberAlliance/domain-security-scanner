PROJECT			:= github.com/GlobalCyberAlliance/GCADMARCRiskScanner

DEP				:= $(shell which dep 2>/dev/null)
GO				:= $(shell which go 2>/dev/null)
GO_BUILD_FLAGS	:=
GO_BUILD		:= $(GO) build $(GO_BUILD_FLAGS)
GO_TEST_FLAGS	:= -v -short
GO_TEST			:= $(GO) test $(GO_TEST_FLAGS)
GO_BENCH_FLAGS	:= -short -bench=. -benchmem
GO_BENCH		:= $(GO) test $(GO_BENCH_FLAGS)

TARGETS			:= bin/drs

all: deps bin $(TARGETS)

bin:
	mkdir -p $@

bin/%: $(shell find . -name "*.go" -type f)
ifeq ("${GO}","")
	$(error Cannot find "go" in your $$PATH)
endif
	$(GO_BUILD) -o $@ $(PROJECT)/cmd/$*

deps: $(DEP)
ifeq ("${DEP}","")
	$(error Cannot find "dep" in your $$PATH)
endif
	$(DEP) ensure

clean:
	-rm -rf bin

test:
ifeq ("${GO}","")
	$(error Cannot find "go" in your $$PATH)
endif
	$(GO_TEST) ./...

bench:
ifeq ("${GO}","")
	$(error Cannot find "go" in your $$PATH)
endif
	$(GO_BENCH) ./...

.PHONY: deps clean test bench
