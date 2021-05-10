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
	CrowdSecLAPIUrl      string          `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey      string          `yaml:"crowdsec_lapi_key"`
	CloudflareAPIToken   string          `yaml:"cloudfare_api_token"`
	CloudflareAccountID  string          `yaml:"cloudfare_account_id"`
	CloudflareZoneID     string          `yaml:"cloudfare_zone_id"`
	CloudflareIPListName string          `yaml:"cloudfare_ip_list_name"`
	updateFrequency      time.Duration
	Action               string          `yaml:"action"`
	Daemon               bool            `yaml:"daemon"`
	UpdateFrequencyYAML  string          `yaml:"update_frequency"`
	LogMode              string          `yaml:"log_mode"`
	LogDir               string          `yaml:"log_dir"`
	LogLevel             log.Level       `yaml:"log_level"`
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
