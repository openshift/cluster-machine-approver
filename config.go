package main

import (
	"encoding/json"
	"io/ioutil"

	kyaml "k8s.io/apimachinery/pkg/util/yaml"

	"k8s.io/klog/v2"
)

type ClusterMachineApproverConfig struct {
	NodeClientCert NodeClientCert `json:"nodeClientCert,omitempty"`
}

type NodeClientCert struct {
	Disabled bool `json:"disabled,omitempty"`
}

func loadConfig(cliConfig string) ClusterMachineApproverConfig {
	config := ClusterMachineApproverConfig{}
	defer func() {
		klog.Infof("machine approver config: %+v", config)
	}()

	if len(cliConfig) == 0 {
		klog.Info("using default as no cli config specified")
		return config
	}

	content, err := ioutil.ReadFile(cliConfig)
	if err != nil {
		klog.Infof("using default as failed to load config %s: %v", cliConfig, err)
		return config
	}
	if len(content) == 0 {
		klog.Infof("using default as config %s is empty", cliConfig)
		return config
	}

	data, err := kyaml.ToJSON(content)
	if err != nil {
		klog.Infof("using default as failed to convert config %s to JSON: %v", cliConfig, err)
		return config
	}

	if err := json.Unmarshal(data, &config); err != nil {
		klog.Infof("using default as failed to unmarshal config %s as JSON: %v", cliConfig, err)
		return config
	}

	return config
}
