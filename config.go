package main

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type CloudflareZone struct {
	ID          string   `yaml:"zone_id"`
	Remediation []string `yaml:"remediation,omitempty"`
}
type CloudflareAccount struct {
	ID           string           `yaml:"id"`
	Zones        []CloudflareZone `yaml:"zones"`
	Token        string           `yaml:"token"`
	IPListPrefix string           `yaml:"ip_list_prefix"`
}
type CloudflareConfig struct {
	Accounts        []CloudflareAccount `yaml:"accounts"`
	UpdateFrequency time.Duration       `yaml:"update_frequency"`
}

type bouncerConfig struct {
	CrowdSecLAPIUrl             string           `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey             string           `yaml:"crowdsec_lapi_key"`
	CrowdsecUpdateFrequencyYAML string           `yaml:"crowdsec_update_frequency"`
	CloudflareConfig            CloudflareConfig `yaml:"cloudflare_config"`
	Daemon                      bool             `yaml:"daemon"`
	LogMode                     string           `yaml:"log_mode"`
	LogDir                      string           `yaml:"log_dir"`
	LogLevel                    log.Level        `yaml:"log_level"`
}

// NewConfig creates bouncerConfig from the file at provided path
func NewConfig(configPath string) (*bouncerConfig, error) {
	var LogOutput *lumberjack.Logger //io.Writer
	config := &bouncerConfig{}
	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.UnmarshalStrict(configBuff, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}
	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIdSet := make(map[string]bool)    // for verifying that each zoneID is unique
	validRemedy := map[string]bool{"challenge": true, "block": true, "js_challenge": true}

	for i, account := range config.CloudflareConfig.Accounts {
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}
		if account.IPListPrefix == "" {
			config.CloudflareConfig.Accounts[i].IPListPrefix = "crowdsec"
		}

		for i, zone := range account.Zones {
			if len(zone.Remediation) == 0 {
				account.Zones[i].Remediation = []string{"challenge"}
			}
			for _, r := range zone.Remediation {
				if _, ok := validRemedy[r]; !ok {
					return nil, fmt.Errorf("invalid remediation '%s', valid choices are either of 'block', 'js_challenge', 'challenge'", r)
				}
			}

			if _, ok := zoneIdSet[zone.ID]; ok {
				return nil, fmt.Errorf("zone id %s is duplicated", zone.ID)
			}
			zoneIdSet[zone.ID] = true

		}

	}
	/*Configure logging*/
	if err = types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		LogOutput = &lumberjack.Logger{
			Filename:   config.LogDir + "/cs-cloudflare-bouncer.log",
			MaxSize:    500, //megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, //disabled by default
		}
		log.SetOutput(LogOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &bouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	return config, nil
}

// func main() {
// 	z, err := NewConfig("./cs-cloudflare-bouncer.yaml")
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Printf("%+v", z)

// }
