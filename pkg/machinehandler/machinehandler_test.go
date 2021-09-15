package machinehandler

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fakeMachineRoundTripper helps to construct fake rest client to handle /api & /apis requests
// when client is requesting /apis, will return apigroups with capi & ocp machine groups
type fakeMachineRoundTripper struct{}

func (f fakeMachineRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	data := ""
	if strings.HasSuffix(req.URL.Path, "/api") {
		data = `
		{
			"kind": "APIVersions",
			"versions": [
			  "v1"
			],
			"serverAddressByClientCIDRs": [
			  {
				"clientCIDR": "0.0.0.0/0"
			  }
			]
		}`
	} else if strings.HasSuffix(req.URL.Path, "/apis") {
		data = `{
			"kind": "APIGroupList",
			"apiVersion": "v1",
			"groups": [
				{
					"name": "cluster.x-k8s.io",
					"versions": [
					  {
						"groupVersion": "cluster.x-k8s.io/v1alpha4",
						"version": "v1alpha4"
					  }
					],
					"preferredVersion": {
					  "groupVersion": "cluster.x-k8s.io/v1alpha4",
					  "version": "v1alpha4"
					}
				},
				{
					"name": "machine.openshift.io",
					"versions": [
					  {
						"groupVersion": "machine.openshift.io/v1beta1",
						"version": "v1beta1"
					  }
					],
					"preferredVersion": {
					  "groupVersion": "machine.openshift.io/v1beta1",
					  "version": "v1beta1"
					}
				  }
			]
		}`
	}
	res := &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBufferString(data)),
	}
	return res, nil
}
func createUnstructuredMachine(apiVersion, name, namespace, ip, nodeName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": apiVersion,
			"kind":       "Machine",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{},
			"status": map[string]interface{}{
				"addresses": []interface{}{
					map[string]interface{}{
						"address": nodeName,
						"type":    "InternalDNS",
					},
					map[string]interface{}{
						"address": ip,
						"type":    "InternalIP",
					},
				},
				"nodeRef": map[string]interface{}{
					"kind": "Node",
					"name": nodeName,
				},
			},
		},
	}
}

func Test_authorizeCSR(t *testing.T) {
	capiMachine1 := createUnstructuredMachine("cluster.x-k8s.io/v1alpha4", "capi-machine1", "capi-machine1", "10.0.128.123", "ip-10-0-128-123.ec2.internal")
	capiMachine2 := createUnstructuredMachine("cluster.x-k8s.io/v1alpha4", "capi-machine2", "capi-machine2", "10.0.128.124", "ip-10-0-128-124.ec2.internal")
	ocpMachine1 := createUnstructuredMachine("machine.openshift.io/v1beta1", "ocp-machine1", "ocp-machine1", "10.0.172.123", "ip-10-0-172-123.ec2.internal")
	ocpmachine2 := createUnstructuredMachine("machine.openshift.io/v1beta1", "ocp-machine2", "ocp-machine2", "10.0.172.124", "ip-10-0-172-124.ec2.internal")
	cl := fake.NewClientBuilder().WithObjects(capiMachine1, capiMachine2, ocpMachine1, ocpmachine2).Build()
	type args struct {
		apiGroup  string
		client    client.Client
		config    *rest.Config
		ctx       context.Context
		namespace string
	}

	tests := []struct {
		name             string
		args             args
		wantErr          bool
		wantMachineNames []string
	}{
		{
			name: "should list cluster-api machines in one namespace",
			args: args{
				apiGroup: "cluster.x-k8s.io",
				client:   cl,
				config: &rest.Config{
					Transport: fakeMachineRoundTripper{},
				},
				ctx:       context.TODO(),
				namespace: "capi-machine1",
			},
			wantErr:          false,
			wantMachineNames: []string{"capi-machine1"},
		},
		{
			name: "should list openshift machines in all namespaces when namespace is empty",
			args: args{
				apiGroup: "machine.openshift.io",
				client:   cl,
				config: &rest.Config{
					Transport: fakeMachineRoundTripper{},
				},
				ctx:       context.TODO(),
				namespace: "",
			},
			wantErr:          false,
			wantMachineNames: []string{"ocp-machine1", "ocp-machine2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := MachineHandler{
				APIGroup:  tt.args.apiGroup,
				Client:    tt.args.client,
				Config:    tt.args.config,
				Ctx:       tt.args.ctx,
				Namespace: tt.args.namespace,
			}
			machines, err := handler.ListMachines()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error returned. wantErr: %t. err: %v.", tt.wantErr, err)
			}
			if len(machines) != len(tt.wantMachineNames) {
				t.Errorf("unexpected machines returned. want machine names: %v, got machines: %v.", tt.wantMachineNames, machines)
				return
			}
			for i, m := range machines {
				if m.Name != tt.wantMachineNames[i] {
					t.Errorf("unexpected machines returned. want machine names: %v, got machines: %v.", tt.wantMachineNames, machines)
					break
				}
			}
		})
	}

}
