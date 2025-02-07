// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// IBMCloudCSIDriverConfigSpecApplyConfiguration represents a declarative configuration of the IBMCloudCSIDriverConfigSpec type for use
// with apply.
type IBMCloudCSIDriverConfigSpecApplyConfiguration struct {
	EncryptionKeyCRN *string `json:"encryptionKeyCRN,omitempty"`
}

// IBMCloudCSIDriverConfigSpecApplyConfiguration constructs a declarative configuration of the IBMCloudCSIDriverConfigSpec type for use with
// apply.
func IBMCloudCSIDriverConfigSpec() *IBMCloudCSIDriverConfigSpecApplyConfiguration {
	return &IBMCloudCSIDriverConfigSpecApplyConfiguration{}
}

// WithEncryptionKeyCRN sets the EncryptionKeyCRN field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the EncryptionKeyCRN field is set to the value of the last call.
func (b *IBMCloudCSIDriverConfigSpecApplyConfiguration) WithEncryptionKeyCRN(value string) *IBMCloudCSIDriverConfigSpecApplyConfiguration {
	b.EncryptionKeyCRN = &value
	return b
}
