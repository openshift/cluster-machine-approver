# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.26.1

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
ENVTEST_PLATFORM := $(shell go env GOOS)-$(shell go env GOARCH)
ENVTEST_ASSETS := $(PROJECT_DIR)/bin/k8s/$(ENVTEST_K8S_VERSION)-$(ENVTEST_PLATFORM)
ENVTEST_URL := https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v$(ENVTEST_K8S_VERSION)/envtest-v$(ENVTEST_K8S_VERSION)-$(ENVTEST_PLATFORM).tar.gz

GO111MODULE = on
export GO111MODULE
GOFLAGS ?= -mod=vendor
export GOFLAGS
GOPROXY ?=
export GOPROXY
BUILD_IMAGE ?= registry.ci.openshift.org/openshift/release:golang-1.19


NO_DOCKER ?= 0

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

$(ENVTEST_ASSETS)/.ready:
	mkdir -p "$(ENVTEST_ASSETS)"
	curl --fail --location --retry 3 "$(ENVTEST_URL)" -o "$(ENVTEST_ASSETS)/assets.tar.gz"
	tar -xzf "$(ENVTEST_ASSETS)/assets.tar.gz" -C "$(ENVTEST_ASSETS)" --strip-components=2
	test -x "$(ENVTEST_ASSETS)/kube-apiserver" -a -x "$(ENVTEST_ASSETS)/etcd" -a -x "$(ENVTEST_ASSETS)/kubectl"
	rm "$(ENVTEST_ASSETS)/assets.tar.gz"
	touch "$@"

unit: $(ENVTEST_ASSETS)/.ready
	KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS)" ./hack/ci-test.sh
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
