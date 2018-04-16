PROJECT			:= github.com/GlobalCyberAlliance/GCADMARCRiskScanner

DEP				:= $(shell which dep)
GO				:= $(shell which go)
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
	$(GO_BUILD) -o $@ $(PROJECT)/cmd/$*

deps: $(DEP)
	$(DEP) ensure

clean:
	-rm -rf bin

test: $(GLIDE)
	$(GO_TEST) $(shell $(GLIDE) novendor)

bench: $(GLIDE)
	$(GO_BENCH) $(shell $(GLIDE) novendor)

.PHONY: deps clean test bench
