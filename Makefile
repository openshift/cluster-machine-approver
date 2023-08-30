# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.26

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
ENVTEST = go run ${PROJECT_DIR}/vendor/sigs.k8s.io/controller-runtime/tools/setup-envtest

GO111MODULE = on
export GO111MODULE
GOFLAGS ?= -mod=vendor
export GOFLAGS
GOPROXY ?=
export GOPROXY
BUILD_IMAGE ?= registry.ci.openshift.org/openshift/release:golang-1.19


NO_DOCKER ?= 1

ifeq ($(shell command -v podman > /dev/null 2>&1 ; echo $$? ), 0)
	ENGINE=podman
else ifeq ($(shell command -v docker > /dev/null 2>&1 ; echo $$? ), 0)
	ENGINE=docker
else
	NO_DOCKER=1
endif

USE_DOCKER ?= 0
ifeq ($(USE_DOCKER), 1)
	ENGINE=docker
endif

ifeq ($(NO_DOCKER), 1)
  DOCKER_CMD =
  IMAGE_BUILD_CMD = imagebuilder
else
  DOCKER_CMD := $(ENGINE) run --env GO111MODULE=$(GO111MODULE) --env GOFLAGS=$(GOFLAGS) --rm -v "$(PWD)":/go/src/github.com/openshift/cluster-machine-approver:Z  -w /go/src/github.com/openshift/cluster-machine-approver $(BUILD_IMAGE)
  IMAGE_BUILD_CMD = $(ENGINE) build
endif

all build:
	$(DOCKER_CMD) go build -o machine-approver .
.PHONY: all build

test: unit
.PHONY: test

unit:
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path --bin-dir $(PROJECT_DIR)/bin)" ./hack/ci-test.sh
.PHONY: unit

.PHONY: goimports
goimports: ## Go fmt your code
	$(DOCKER_CMD) hack/goimports.sh .

images:
ifeq ($(NO_DOCKER), 1)
	./hack/imagebuilder.sh
endif
	$(IMAGE_BUILD_CMD) -f Dockerfile -t openshift/origin-cluster-machine-approver:latest .
.PHONY: images

clean:
	$(DOCKER_CMD) $(RM) ./machine-approver
.PHONY: clean

test-e2e: ## Run e2e tests
	hack/e2e.sh
.PHONY: test-e2e

.PHONY: vendor
vendor:
	$(DOCKER_CMD) hack/go-mod.sh
