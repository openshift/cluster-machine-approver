GO111MODULE = on
export GO111MODULE
GOFLAGS ?= -mod=vendor
export GOFLAGS
GOPROXY ?=
export GOPROXY

all build:
	go build -o machine-approver .
.PHONY: all build

test:
	KUBEBUILDER_CONTROLPLANE_START_TIMEOUT=10m hack/ci-test.sh
.PHONY: test

unit:
	go test -v ./...
.PHONY: unit

.PHONY: goimports
goimports: ## Go fmt your code
	hack/goimports.sh .

images:
	imagebuilder -f Dockerfile -t openshift/origin-cluster-machine-approver:latest .
.PHONY: images

clean:
	$(RM) ./cluster-machine-approver
.PHONY: clean

test-e2e: ## Run e2e tests
	hack/e2e.sh
.PHONY: test-e2e

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor
	go mod verify
