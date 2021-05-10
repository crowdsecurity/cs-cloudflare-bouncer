package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

type blockerConfig struct {
	CrowdSecLAPIUrl      string `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey      string `yaml:"crowdsec_lapi_key"`
	CloudflareAPIToken   string `yaml:"cloudfare_api_token"`
	CloudflareAccountID  string `yaml:"cloudfare_account_id"`
	CloudflareZoneID     string `yaml:"cloudfare_zone_id"`
	CloudflareIPListName string `yaml:"cloudfare_ip_list_name"`
	updateFrequency      time.Duration
	Action               string `yaml:"action"`
	Daemon               bool   `yaml:"daemon"`
	UpdateFrequencyYAML  string `yaml:"update_frequency"`
}

// NewConfig creates blockerConfig from the file at provided path
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

	if config.Action == "" {
		config.Action = "block"
	}

	if config.CloudflareIPListName == "" {
		config.CloudflareIPListName = "crowdsec"
	}

	return config, nil
}
