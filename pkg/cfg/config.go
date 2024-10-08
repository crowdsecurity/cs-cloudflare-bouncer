package cfg

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/yamlpatch"
)

var TotalIPListCapacity int = 10000

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
	CrowdSecInsecureSkipVerify  bool             `yaml:"crowdsec_insecure_skip_verify"`
	CrowdsecUpdateFrequencyYAML string           `yaml:"crowdsec_update_frequency"`
	IncludeScenariosContaining  []string         `yaml:"include_scenarios_containing"`
	ExcludeScenariosContaining  []string         `yaml:"exclude_scenarios_containing"`
	OnlyIncludeDecisionsFrom    []string         `yaml:"only_include_decisions_from"`
	CloudflareConfig            CloudflareConfig `yaml:"cloudflare_config"`
	Daemon                      bool             `yaml:"daemon"`
	Logging                     LoggingConfig    `yaml:",inline"`
	PrometheusConfig            PrometheusConfig `yaml:"prometheus"`
	KeyPath                     string           `yaml:"key_path"`
	CertPath                    string           `yaml:"cert_path"`
	CAPath                      string           `yaml:"ca_cert_path"`
}

func MergedConfig(configPath string) ([]byte, error) {
	patcher := yamlpatch.NewPatcher(configPath, ".local")
	data, err := patcher.MergedPatchContent()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// NewConfig creates bouncerConfig from the file at provided path
func NewConfig(reader io.Reader) (*bouncerConfig, error) {
	config := &bouncerConfig{}

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	configBuff := csstring.StrictExpand(string(content), os.LookupEnv)

	err = yaml.Unmarshal([]byte(configBuff), &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	if err = config.Logging.setup("crowdsec-cloudflare-bouncer.log"); err != nil {
		return nil, fmt.Errorf("failed to setup logging: %w", err)
	}

	accountIDSet := make(map[string]bool) // for verifying that each account ID is unique
	zoneIDSet := make(map[string]bool)    // for verifying that each zoneID is unique
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
				}
				if a == "challenge" {
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

			if _, ok := zoneIDSet[zone.ID]; ok {
				return nil, fmt.Errorf("zone id %s is duplicated", zone.ID)
			}
			zoneIDSet[zone.ID] = true
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

func lineComment(l string, zoneByID map[string]cloudflare.Zone, accountByID map[string]cloudflare.Account) string {
	words := strings.Split(l, " ")
	lastWord := words[len(words)-1]
	if zone, ok := zoneByID[lastWord]; ok {
		return zone.Name
	}
	if account, ok := accountByID[lastWord]; ok {
		return account.Name
	}
	if strings.Contains(l, "total_ip_list_capacity") {
		return "only this many latest IP decisions would be kept"
	}
	if strings.Contains(l, "exclude_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios containing either of provided word"
	}
	if strings.Contains(l, "include_scenarios_containing") {
		return "ignore IPs banned for triggering scenarios not containing either of provided word"
	}
	if strings.Contains(l, "only_include_decisions_from") {
		return `only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]`
	}
	return ""
}

func ConfigTokens(tokens string, baseConfigPath string) (string, error) {
	baseConfig := &bouncerConfig{}
	hasBaseConfig := true
	configBuff, err := os.ReadFile(baseConfigPath)
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
		comment := lineComment(line, zoneByID, accountByID)
		if comment != "" {
			lines[i] = line + " # " + comment
		}
	}

	return strings.Join(lines, "\n"), nil
}

func setDefaults(cfg *bouncerConfig) {
	cfg.CrowdSecLAPIUrl = "http://localhost:8080/"
	cfg.CrowdsecUpdateFrequencyYAML = "10s"

	cfg.Daemon = true
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

	cfg.PrometheusConfig = PrometheusConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    "2112",
	}
}
