package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

type ZoneConfig struct {
	ID        string              `yaml:"zone_id"`
	Actions   []string            `yaml:"actions,omitempty"`
	ActionSet map[string]struct{} `yaml:",omitempty"`
}
type AccountConfig struct {
	ID                  string       `yaml:"id"`
	ZoneConfigs         []ZoneConfig `yaml:"zones"`
	Token               string       `yaml:"token"`
	IPListPrefix        string       `yaml:"ip_list_prefix"`
	DefaultAction       string       `yaml:"default_action"`
	TotalIPListCapacity *int         `yaml:"total_ip_list_capacity"`
}
type CloudflareConfig struct {
	Accounts        []AccountConfig `yaml:"accounts"`
	UpdateFrequency time.Duration   `yaml:"update_frequency"`
}
type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_addr"`
	ListenPort    string `yaml:"listen_port"`
}

type bouncerConfig struct {
	CrowdSecLAPIUrl             string           `yaml:"crowdsec_lapi_url"`
	CrowdSecLAPIKey             string           `yaml:"crowdsec_lapi_key"`
	CrowdsecUpdateFrequencyYAML string           `yaml:"crowdsec_update_frequency"`
	IncludeScenariosContaining  []string         `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining  []string         `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom    []string         `yaml:"only_include_decisions_from"`
	CloudflareConfig            CloudflareConfig `yaml:"cloudflare_config"`
	Daemon                      bool             `yaml:"daemon"`
	LogMode                     string           `yaml:"log_mode"`
	LogDir                      string           `yaml:"log_dir"`
	LogLevel                    log.Level        `yaml:"log_level"`
	LogMaxSize                  int              `yaml:"log_max_size"`
	LogMaxAge                   int              `yaml:"log_max_age"`
	LogMaxFiles                 int              `yaml:"log_max_backups"`
	CompressLogs                *bool            `yaml:"compress_logs"`
	PrometheusConfig            PrometheusConfig `yaml:"prometheus"`
}

// NewConfig creates bouncerConfig from the file at provided path
func NewConfig(configPath string) (*bouncerConfig, error) {
	config := &bouncerConfig{}
	configBuff, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s : %v", configPath, err)
	}

	err = yaml.Unmarshal(configBuff, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}

	/*Configure logging*/
	if err = types.SetDefaultLoggerConfig(config.LogMode, config.LogDir, config.LogLevel, 0, 0, 0, nil); err != nil {
		log.Fatal(err.Error())
	}
	if config.LogMode == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		_maxsize := 40
		if config.LogMaxSize != 0 {
			_maxsize = config.LogMaxSize
		}
		_maxfiles := 3
		if config.LogMaxFiles != 0 {
			_maxfiles = config.LogMaxFiles
		}
		_maxage := 30
		if config.LogMaxAge != 0 {
			_maxage = config.LogMaxAge
		}
		_compress := true
		if config.CompressLogs != nil {
			_compress = *config.CompressLogs
		}
		logOutput := &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-cloudflare-bouncer.log",
			MaxSize:    _maxsize,
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,
			Compress:   _compress,
		}
		log.SetOutput(logOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
	} else if config.LogMode != "stdout" {
		return &bouncerConfig{}, fmt.Errorf("log mode '%s' unknown, expecting 'file' or 'stdout'", config.LogMode)
	}

	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIdSet := make(map[string]bool)    // for verifying that each zoneID is unique
	validAction := map[string]bool{"challenge": true, "block": true, "js_challenge": true, "managed_challenge": true}
	validChoiceMsg := "valid choices are either of 'block', 'js_challenge', 'challenge', 'managed_challenge'"

	for i, account := range config.CloudflareConfig.Accounts {
		if _, ok := accountIDSet[account.ID]; ok {
			return nil, fmt.Errorf("the account '%s' is duplicated", account.ID)
		}
		accountIDSet[account.ID] = true

		if account.Token == "" {
			return nil, fmt.Errorf("the account '%s' is missing token", account.ID)
		}

		if account.TotalIPListCapacity == nil {
			config.CloudflareConfig.Accounts[i].TotalIPListCapacity = &TotalIPListCapacity
		}
		if account.IPListPrefix == "" {
			config.CloudflareConfig.Accounts[i].IPListPrefix = "crowdsec"
		}

		if len(account.DefaultAction) == 0 {
			return nil, fmt.Errorf("account %s has no default action", account.ID)
		}
		if _, ok := validAction[account.DefaultAction]; !ok {
			return nil, fmt.Errorf("account %s 's default action is invalid. %s ", account.ID, validChoiceMsg)
		}
		zoneUsingChallenge := make([]string, 0)
		for j, zone := range account.ZoneConfigs {
			config.CloudflareConfig.Accounts[i].ZoneConfigs[j].ActionSet = map[string]struct{}{}
			if len(zone.Actions) == 0 {
				return nil, fmt.Errorf("account %s 's zone %s has no action", account.ID, zone.ID)
			}
			defaultActionIsSupported := false
			for _, a := range zone.Actions {
				if _, ok := validAction[a]; !ok {
					return nil, fmt.Errorf("invalid actions '%s', %s", a, validChoiceMsg)
				} else if a == "challenge" {
					zoneUsingChallenge = append(zoneUsingChallenge, zone.ID)
				}
				if a == account.DefaultAction {
					defaultActionIsSupported = true
				}
				config.CloudflareConfig.Accounts[i].ZoneConfigs[j].ActionSet[a] = struct{}{}
			}

			if !defaultActionIsSupported {
				return nil, fmt.Errorf("zone %s doesn't support the default action %s for it's account", zone.ID, account.DefaultAction)
			}

			if _, ok := zoneIdSet[zone.ID]; ok {
				return nil, fmt.Errorf("zone id %s is duplicated", zone.ID)
			}
			zoneIdSet[zone.ID] = true
		}
		if len(zoneUsingChallenge) > 0 {
			log.Warningf(
				"zones %s uses 'challenge' action which is deprecated in favour of 'managed_challenge'. See migration guide at https://docs.crowdsec.net/docs/next/bouncers/cloudflare/#upgrading-from-v00x-to-v01y",
				strings.Join(zoneUsingChallenge, ", "),
			)
		}
	}
	return config, nil
}

func ConfigTokens(tokens string, baseConfigPath string) (string, error) {
	baseConfig := &bouncerConfig{}
	hasBaseConfig := true
	configBuff, err := ioutil.ReadFile(baseConfigPath)
	if err != nil {
		hasBaseConfig = false
	}

	if hasBaseConfig {
		err = yaml.Unmarshal(configBuff, &baseConfig)
		if err != nil {
			return "", err
		}
	} else {
		setDefaults(baseConfig)
	}

	accountConfig := make([]AccountConfig, 0)
	zoneByID := make(map[string]cloudflare.Zone)
	accountByID := make(map[string]cloudflare.Account)
	ctx := context.Background()
	for _, token := range strings.Split(tokens, ",") {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			return "", err
		}
		accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
		if err != nil {
			return "", err
		}
		for i, account := range accounts {
			accountConfig = append(accountConfig, AccountConfig{
				ID:                  account.ID,
				ZoneConfigs:         make([]ZoneConfig, 0),
				Token:               token,
				IPListPrefix:        "crowdsec",
				DefaultAction:       "managed_challenge",
				TotalIPListCapacity: &TotalIPListCapacity,
			})

			api.AccountID = account.ID
			accountByID[account.ID] = account
			zones, err := api.ListZones(ctx)
			if err != nil {
				return "", err
			}

			for _, zone := range zones {
				zoneByID[zone.ID] = zone
				if zone.Account.ID == account.ID {
					accountConfig[i].ZoneConfigs = append(accountConfig[i].ZoneConfigs, ZoneConfig{
						ID:      zone.ID,
						Actions: []string{"managed_challenge"},
					})
				}
			}
		}
	}
	cfConfig := CloudflareConfig{Accounts: accountConfig, UpdateFrequency: time.Second * 10}
	baseConfig.CloudflareConfig = cfConfig
	data, err := yaml.Marshal(baseConfig)
	if err != nil {
		return "", err
	}

	lineString := string(data)
	lines := strings.Split(lineString, "\n")
	if hasBaseConfig {
		lines = append([]string{
			fmt.Sprintf("# Config generated by using %s as base", baseConfigPath),
		},
			lines...,
		)
	} else {
		lines = append([]string{
			fmt.Sprintf("# Base config %s not found, please fill crowdsec credentials. ", baseConfigPath),
		},
			lines...,
		)
	}
	for i, line := range lines {
		words := strings.Split(line, " ")
		lastWord := words[len(words)-1]
		if zone, ok := zoneByID[lastWord]; ok {
			line = fmt.Sprintf("%s #%s", line, zone.Name)
		} else if account, ok := accountByID[lastWord]; ok {
			line = fmt.Sprintf("%s #%s", line, account.Name)
		} else if strings.Contains(line, "total_ip_list_capacity") {
			line = fmt.Sprintf("%s #%s", line, " only this many latest IP decisions would be kept")
		} else if strings.Contains(line, "exclude_scenarios_containing") {
			line = fmt.Sprintf("%s #%s", line, " ignore IPs banned for triggering scenarios containing either of provided word")
		} else if strings.Contains(line, "include_scenarios_containing") {
			line = fmt.Sprintf("%s #%s", line, " ignore IPs banned for triggering scenarios not containing either of provided word")
		} else if strings.Contains(line, "only_include_decisions_from") {
			line = fmt.Sprintf("%s #%s", line, ` only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]`)
		}
		lines[i] = line
	}

	return strings.Join(lines, "\n"), nil
}

func setDefaults(cfg *bouncerConfig) {
	cfg.CrowdSecLAPIUrl = "http://localhost:8080/"
	cfg.CrowdsecUpdateFrequencyYAML = "10s"

	cfg.Daemon = true
	cfg.LogMode = "file"
	cfg.LogDir = "/var/log/"
	cfg.LogLevel = log.InfoLevel
	cfg.ExcludeScenariosContaining = []string{
		"ssh",
		"ftp",
		"smb",
	}
	cfg.OnlyIncludeDecisionsFrom = []string{
		"CAPI",
		"cscli",
		"crowdsec",
		"lists",
	}
	cfg.LogMaxAge = 30
	cfg.LogMaxSize = 40
	cfg.CompressLogs = types.BoolPtr(true)
	cfg.LogMaxFiles = 3

	cfg.PrometheusConfig = PrometheusConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    "2112",
	}
}
