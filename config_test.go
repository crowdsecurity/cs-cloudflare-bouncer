package main

import (
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestNewConfig(t *testing.T) {
	type args struct {
		configPath string
	}
	tests := []struct {
		name    string
		args    args
		want    *bouncerConfig
		wantErr bool
	}{
		{
			name: "valid",
			args: args{"./test_data/valid_config.yaml"},
			want: &bouncerConfig{
				CrowdSecLAPIUrl:             "http://localhost:8080/",
				CrowdSecLAPIKey:             "${LAPI_KEY}",
				CrowdsecUpdateFrequencyYAML: "10s",
				CloudflareConfig: CloudflareConfig{
					Accounts: []AccountConfig{
						{
							ID:                  "${CF_ACC_ID}",
							TotalIPListCapacity: &TotalIPListCapacity,
							ZoneConfigs: []ZoneConfig{
								{
									ID:      "${CF_ZONE_ID}",
									Actions: []string{"challenge"},
									ActionSet: map[string]struct{}{
										"challenge": {},
									},
								},
							},
							Token:         "${CF_TOKEN}",
							IPListPrefix:  "crowdsec",
							DefaultAction: "challenge",
						},
					},
					UpdateFrequency: time.Second * 30,
				},
				Daemon:    false,
				LogMode:   "stdout",
				LogDir:    "/var/log/",
				LogLevel:  log.InfoLevel,
				CachePath: "/var/lib/crowdsec/crowdsec-cloudflare-bouncer/cache/cloudflare-cache.json",
			},
			wantErr: false,
		},
		{
			name:    "invalid time",
			args:    args{"/test_data/invalid_config_time.yaml"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid time",
			args:    args{"/test_data/invalid_config_remedy.yaml"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewConfig(tt.args.configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfig() error = %+v, wantErr %+v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
