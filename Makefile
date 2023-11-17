PROJECT			 := github.com/GlobalCyberAlliance/domain-security-scanner
GO				 := $(shell which go 2>/dev/null)
GOFIELDALIGNMENT := $(shell which fieldalignment 2>/dev/null)
GOFUMPT			 := $(shell which gofumpt 2>/dev/null)
GOLINTER		 := $(shell which staticcheck 2>/dev/null)
GO_BENCH_FLAGS	 := -short -bench=. -benchmem
GO_BENCH		 := $(GO) test $(GO_BENCH_FLAGS)
GO_BUILD		 := CGO_ENABLED=0 $(GO) build -ldflags "-s -w" -trimpath
GO_FORMAT		 := $(GOFUMPT) -w
GO_OPTIMIZE		 := $(GOFIELDALIGNMENT) -fix
GO_TEST			 := $(GO) test -v -short
GO_TIDY			 := $(GO) mod tidy
TARGETS			 := bin/dss

all: check-dependencies prepare bin $(TARGETS) clean

bin:
	@mkdir -p bin
	@echo "Building binaries..."

bin/%: $(shell find . -name "*.go" -type f)
	@echo "Building $@..."
	@cd build && $(GO_BUILD) -o ../$@ $(PROJECT)/cmd/$*

check-dependencies:
	@echo "Checking dependencies..."
	@if [ -z "${GO}" ]; then \
		echo "Cannot find 'go' in your $$PATH"; \
		exit 1; \
	fi
	@if [ -z "${GOFIELDALIGNMENT}" ]; then \
		echo "Cannot find 'fieldalignment' in your $$PATH"; \
		exit 1; \
	fi

clean:
	@echo "Cleaning temporary build directory..."
	@rm -rf build

format:
	@if [ -z "${GOFUMPT}" ]; then \
		echo "Cannot find 'gofumpt' in your $$PATH"; \
		exit 1; \
	fi
	@echo "Formatting code..."
	@$(GO_FORMAT) $(PWD)

lint:
	@if [ -z "${GOLINTER}" ]; then \
		echo "Cannot find 'staticcheck' in your $$PATH"; \
		exit 1; \
	fi
	@echo "Running linter..."
	@$(GOLINTER) ./...

prepare:
	@echo "Cleaning previous builds..."
	@rm -rf bin build
	@mkdir -p bin build
	@$(GO_TIDY)
	@echo "Creating temporary build directory..."
	@cp -r cmd go.* pkg ./build/
	@echo "Optimizing struct field alignment..."
	@cd build && $(GO_OPTIMIZE) ./... > /dev/null 2>&1 || true