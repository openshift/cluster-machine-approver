all build:
	go build -o machine-approver .
.PHONY: all build

images:
	imagebuilder -f Dockerfile -t openshift/origin-cluster-machine-approver:latest .
.PHONY: images

clean:
	$(RM) ./cluster-machine-approver
.PHONY: clean