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
	APIGroup string
	Client   client.Client
	Config   *rest.Config
	Ctx      context.Context
}

type Machine struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            MachineStatus `json:"status,omitempty"`
}
type MachineStatus struct {
	NodeRef   *corev1.ObjectReference `json:"nodeRef,omitempty"`
	Addresses []corev1.NodeAddress    `json:"addresses,omitempty"`
}

// ListMachines list all machines using given client
func (m *MachineHandler) ListMachines() ([]Machine, error) {
	APIVersion, err := m.getAPIGroupPreferredVersion()
	if err != nil {
		return nil, err
	}

	unstructuredMachineList := &unstructured.UnstructuredList{}
	unstructuredMachineList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   m.APIGroup,
		Kind:    "MachineList",
		Version: APIVersion,
	})
	if err := m.Client.List(m.Ctx, unstructuredMachineList); err != nil {
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
func (m *MachineHandler) getAPIGroupPreferredVersion() (string, error) {
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
		if group.Name == m.APIGroup {
			return group.PreferredVersion.Version, nil
		}
	}

	return "", fmt.Errorf("failed to find API group %q", m.APIGroup)
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
