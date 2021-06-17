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

type CloudflareZone struct {
	ID        string              `yaml:"zone_id"`
	Actions   []string            `yaml:"actions,omitempty"`
	ActionSet map[string]struct{} `yaml:",omitempty"`
}
type CloudflareAccount struct {
	ID            string           `yaml:"id"`
	Zones         []CloudflareZone `yaml:"zones"`
	Token         string           `yaml:"token"`
	IPListPrefix  string           `yaml:"ip_list_prefix"`
	DefaultAction string           `yaml:"default_action"`
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

	err = yaml.Unmarshal(configBuff, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s : %v", configPath, err)
	}
	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIdSet := make(map[string]bool)    // for verifying that each zoneID is unique
	validAction := map[string]bool{"challenge": true, "block": true, "js_challenge": true}
	validChoiceMsg := "valid choices are either of 'block', 'js_challenge', 'challenge'"

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

		if len(account.DefaultAction) == 0 {
			return nil, fmt.Errorf("account %s has no default action", account.ID)
		}
		if _, ok := validAction[account.DefaultAction]; !ok {
			return nil, fmt.Errorf("account %s 's default action is invalid. %s ", account.ID, validChoiceMsg)
		}

		for j, zone := range account.Zones {
			config.CloudflareConfig.Accounts[i].Zones[j].ActionSet = map[string]struct{}{}
			if len(zone.Actions) == 0 {
				return nil, fmt.Errorf("account %s 's zone %s has no action", account.ID, zone.ID)
			}
			for _, a := range zone.Actions {
				if _, ok := validAction[a]; !ok {
					return nil, fmt.Errorf("invalid actions '%s', %s", a, validChoiceMsg)
				}
				config.CloudflareConfig.Accounts[i].Zones[j].ActionSet[a] = struct{}{}
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

func ConfigTokens(tokens string, baseConfigPath string) error {
	baseConfig := &bouncerConfig{}
	configBuff, err := ioutil.ReadFile(baseConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read %s : %v", baseConfigPath, err)
	}

	err = yaml.Unmarshal(configBuff, &baseConfig)
	if err != nil {
		return err
	}

	accountConfig := make([]CloudflareAccount, 0)
	zoneByID := make(map[string]cloudflare.Zone)
	accountByID := make(map[string]cloudflare.Account)
	for _, token := range strings.Split(tokens, ",") {
		api, err := cloudflare.NewWithAPIToken(token)
		if err != nil {
			log.Fatal(err)
		}
		ctx := context.Background()
		accounts, _, err := api.Accounts(ctx, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}
		for i, account := range accounts {
			accountConfig = append(accountConfig, CloudflareAccount{
				ID:           account.ID,
				Zones:        make([]CloudflareZone, 0),
				Token:        token,
				IPListPrefix: "crowdsec",
			})

			api.AccountID = account.ID
			accountByID[account.ID] = account
			zones, err := api.ListZones(ctx)
			if err != nil {
				log.Fatal(err)
			}

			for _, zone := range zones {
				zoneByID[zone.ID] = zone
				if zone.Account.ID == account.ID {
					accountConfig[i].Zones = append(accountConfig[i].Zones, CloudflareZone{
						ID:      zone.ID,
						Actions: []string{"challenge"},
					})
				}
			}
		}
	}
	cfConfig := CloudflareConfig{Accounts: accountConfig, UpdateFrequency: time.Second * 10}
	baseConfig.CloudflareConfig = cfConfig
	data, err := yaml.Marshal(baseConfig)
	if err != nil {
		return err
	}

	lines := string(data)
	for _, line := range strings.Split(lines, "\n") {
		words := strings.Split(line, " ")
		lastWord := words[len(words)-1]
		if zone, ok := zoneByID[lastWord]; ok {
			fmt.Printf("%s #%s\n", line, zone.Name)
		} else if account, ok := accountByID[lastWord]; ok {
			fmt.Printf("%s #%s\n", line, account.Name)
		} else {
			fmt.Println(line)
		}
	}
	return nil
}
