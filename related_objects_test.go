package main

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	osconfigv1 "github.com/openshift/api/config/v1"
	"sigs.k8s.io/yaml"
)

var _ = Describe("relatedObjects", func() {
	It("should stay in sync with the ClusterOperator manifest", func() {
		manifestPath := filepath.Join("manifests", "05-clusteroperator.yaml")
		data, err := os.ReadFile(manifestPath)
		Expect(err).ToNot(HaveOccurred(), "should be able to read ClusterOperator manifest")

		co := &osconfigv1.ClusterOperator{}
		Expect(yaml.Unmarshal(data, co)).To(Succeed(), "should be able to unmarshal ClusterOperator manifest")

		Expect(co.Status.RelatedObjects).To(Equal(relatedObjects), "Go relatedObjects must match the static ClusterOperator manifest")
	})
})
