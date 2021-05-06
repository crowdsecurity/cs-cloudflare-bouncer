package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
)

type blockerConfig struct {
	CrowdSecLAPIUrl     string `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey     string `yaml:"crowdsec_lapi_key"`
	CloudflareAPIToken  string `yaml:"cloudfare_api_token"`
	CloudflareAccountID string `yaml:"cloudfare_account_id"`
	updateFrequency     time.Duration
	UpdateFrequencyYAML string `yaml:"update_frequency"`
}

func NewConfig(configPath string) (*blockerConfig, error) {
	config := &blockerConfig{}

	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.UnmarshalStrict(configBuff, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

	config.updateFrequency, err = time.ParseDuration(config.UpdateFrequencyYAML)
	if err != nil {
		return nil, fmt.Errorf("invalid update frequency %s : %s", config.UpdateFrequencyYAML, err)
	}

	return config, nil
}
