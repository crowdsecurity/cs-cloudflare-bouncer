# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

GOOS ?= linux
GOARCH ?= amd64

#Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags `git rev-list --tags --max-count=1`)"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"
export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/cs-cloudflare-bouncer/version.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/cs-cloudflare-bouncer/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/cs-cloudflare-bouncer/version.Tag=$(BUILD_TAG)" \
-trimpath
PREFIX?="/"
PID_DIR = $(PREFIX)"/var/run/"
BINARY_NAME=crowdsec-cloudflare-bouncer

RELDIR = "crowdsec-cloudflare-bouncer-${BUILD_VERSION}"

all: clean build

static: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

build: goversion clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

.PHONY: test
test:
	$(GOTEST) ./...

clean:
	@rm -f $(BINARY_NAME)
	@rm -rf ${RELDIR}
	@rm -f crowdsec-cloudflare-bouncer-*.tgz || ""


.PHONY: release
release: build
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf crowdsec-cloudflare-bouncer-$(GOOS)-$(GOARCH).tgz $(RELDIR)

release_static: static
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf crowdsec-cloudflare-bouncer-$(GOOS)-$(GOARCH)-static.tgz $(RELDIR)

include mk/goversion.mk
