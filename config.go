package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/golang/glog"

	kyaml "k8s.io/apimachinery/pkg/util/yaml"
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
		glog.Infof("machine approver config: %+v", config)
	}()

	if len(cliConfig) == 0 {
		glog.Info("using default as no cli config specified")
		return config
	}

	content, err := ioutil.ReadFile(cliConfig)
	if err != nil {
		glog.Infof("using default as failed to load config %s: %v", cliConfig, err)
		return config
	}
	if len(content) == 0 {
		glog.Infof("using default as config %s is empty", cliConfig)
		return config
	}

	data, err := kyaml.ToJSON(content)
	if err != nil {
		glog.Infof("using default as failed to convert config %s to JSON: %v", cliConfig, err)
		return config
	}

	if err := json.Unmarshal(data, &config); err != nil {
		glog.Infof("using default as failed to unmarshal config %s as JSON: %v", cliConfig, err)
		return config
	}

	return config
}
