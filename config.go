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

type bouncerConfig struct {
	CrowdSecLAPIUrl             string        `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey             string        `yaml:"crowdsec_lapi_key"`
	CrowdsecUpdateFrequencyYAML string        `yaml:"crowdsec_update_frequency"`
	CloudflareAPIToken          string        `yaml:"cloudfare_api_token"`
	CloudflareAccountID         string        `yaml:"cloudfare_account_id"`
	CloudflareZoneID            string        `yaml:"cloudfare_zone_id"`
	CloudflareIPListName        string        `yaml:"cloudfare_ip_list_name"`
	CloudflareUpdateFrequency   time.Duration `yaml:"cloudflare_update_frequency"`
	Action                      string        `yaml:"action"`
	Daemon                      bool          `yaml:"daemon"`
	LogMode                     string        `yaml:"log_mode"`
	LogDir                      string        `yaml:"log_dir"`
	LogLevel                    log.Level     `yaml:"log_level"`
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

	if config.Action == "" {
		config.Action = "block"
	}

	if config.Action != "block" && config.Action != "challenge" && config.Action != "js_challenge" {
		return nil, fmt.Errorf("invalid action %s in config, valid actions are either 'challenge', 'block', 'js_challenge'", config.Action)
	}

	// config.CloudflareUpdateFrequency, err = time.ParseDuration(config.CrowdsecUpdateFrequencyYAML)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid update frequency %s : %s", config.CrowdsecUpdateFrequencyYAML, err)
	// }

	// _, err = time.ParseDuration(config.CloudflareUpdateFrequencyYAML)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid update frequency %s : %s", config.CloudflareUpdateFrequencyYAML, err)
	// }

	if config.CloudflareIPListName == "" {
		config.CloudflareIPListName = "crowdsec"
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
