package machinehandler

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrUnstructuredFieldNotFound = fmt.Errorf("field not found")
)

type MachineHandler struct {
	Client    client.Client
	Config    *rest.Config
	Ctx       context.Context
	Namespace string
}

type Machine struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            MachineStatus       `json:"status,omitempty"`
	Spec              MachineProviderSpec `json:"spec,omitempty"`
}
type MachineStatus struct {
	NodeRef   *corev1.ObjectReference `json:"nodeRef,omitempty"`
	Addresses []corev1.NodeAddress    `json:"addresses,omitempty"`
}

type MachineProviderSpec struct {
	ProviderSpec MachineProviderSpecValue `json:"providerSpec,omitempty"`
}
type MachineProviderSpecValue struct {
	Value MachineSpec `json:"value,omitempty"`
}
type MachineSpec struct {
	OsDisk MachineSpecOsDisk `json:"osDisk,omitempty"`
}
type MachineSpecOsDisk struct {
	OsDiskSettings MachineSpecOsDiskSettings `json:"diskSettings,omitempty"`
}
type MachineSpecOsDiskSettings struct {
	EphemeralStorageLocation string `json:"ephemeralStorageLocation,omitempty"`
}

// ListMachines list all machines using given client
func (m *MachineHandler) ListMachines(apiGroupVersion schema.GroupVersion) ([]Machine, error) {
	apiVersion := apiGroupVersion.Version
	if apiVersion == "" {
		var err error
		apiVersion, err = m.getAPIGroupPreferredVersion(apiGroupVersion.Group)
		if err != nil {
			return nil, err
		}
	}

	unstructuredMachineList := &unstructured.UnstructuredList{}
	unstructuredMachineList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   apiGroupVersion.Group,
		Kind:    "MachineList",
		Version: apiVersion,
	})
	listOpts := make([]client.ListOption, 0)
	if m.Namespace != "" {
		listOpts = append(listOpts, client.InNamespace(m.Namespace))
	}
	if err := m.Client.List(m.Ctx, unstructuredMachineList, listOpts...); err != nil {
		return nil, err
	}

	machines := []Machine{}

	stringToTimeHook := func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() == reflect.String && t == reflect.TypeOf(metav1.Time{}) {
			time, err := time.Parse(time.RFC3339, data.(string))
			return metav1.Time{Time: time}, err
		}
		return data, nil
	}

	for _, obj := range unstructuredMachineList.Items {
		machine := Machine{}
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			TagName:    "json",
			Result:     &machine,
			DecodeHook: stringToTimeHook,
		})
		if err != nil {
			return nil, err
		}
		err = decoder.Decode(obj.Object)
		if err != nil {
			return nil, err
		}
		machines = append(machines, machine)
	}

	return machines, nil
}

// getAPIGroupPreferredVersion get preferred API version using API group
func (m *MachineHandler) getAPIGroupPreferredVersion(apiGroup string) (string, error) {
	if m.Config == nil {
		return "", fmt.Errorf("machine handler config can't be nil")
	}

	managementDiscoveryClient, err := discovery.NewDiscoveryClientForConfig(m.Config)
	if err != nil {
		return "", fmt.Errorf("create discovery client failed: %v", err)
	}

	groupList, err := managementDiscoveryClient.ServerGroups()
	if err != nil {
		return "", fmt.Errorf("failed to get ServerGroups: %v", err)
	}

	for _, group := range groupList.Groups {
		if group.Name == apiGroup {
			return group.PreferredVersion.Version, nil
		}
	}

	return "", fmt.Errorf("failed to find API group %q", apiGroup)
}

// FindMatchingMachineFromInternalDNS find matching machine for node using internal DNS
func FindMatchingMachineFromInternalDNS(machines []Machine, nodeName string) (*Machine, error) {
	for _, machine := range machines {
		for _, address := range machine.Status.Addresses {
			if corev1.NodeAddressType(address.Type) == corev1.NodeInternalDNS && address.Address == nodeName {
				return &machine, nil
			}
		}
	}
	return nil, fmt.Errorf("matching machine not found")
}

// FindMatchingMachineFromNodeRef find matching machine for node using node ref
func FindMatchingMachineFromNodeRef(machines []Machine, nodeName string) (*Machine, error) {
	for _, machine := range machines {
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name == nodeName {
			return &machine, nil
		}

	}
	return nil, fmt.Errorf("matching machine not found")
}

// Check whether a machine is an Azure Ephemeral OS Disk VM
func IsMachineAzureEphemeralOsDiskNode(machines []Machine, nodeName string) bool {
	for _, machine := range machines {
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name == nodeName {
			return machine.Spec.ProviderSpec.Value.OsDisk.OsDiskSettings.EphemeralStorageLocation == "Local"
		}
	}
	return false
}
