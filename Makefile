all build:
	go build -o machine-approver .
.PHONY: all build

test:
	go test -v .
.PHONY: test

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
