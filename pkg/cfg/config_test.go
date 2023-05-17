package cfg

import (
	"os"
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
			args: args{"./testdata/valid_config.yaml"},
			want: &bouncerConfig{
				CrowdSecLAPIUrl:             "http://localhost:8080/",
				CrowdSecLAPIKey:             "test",
				CrowdsecUpdateFrequencyYAML: "10s",
				CloudflareConfig: CloudflareConfig{
					Accounts: []AccountConfig{
						{
							ID:                  "test",
							TotalIPListCapacity: &TotalIPListCapacity,
							ZoneConfigs: []ZoneConfig{
								{
									ID:      "test",
									Actions: []string{"challenge"},
									ActionSet: map[string]struct{}{
										"challenge": {},
									},
								},
							},
							Token:         "test",
							IPListPrefix:  "crowdsec",
							DefaultAction: "challenge",
						},
					},
					UpdateFrequency: time.Second * 30,
				},
				Daemon:   false,
				LogMode:  "stdout",
				LogDir:   "/var/log/",
				LogLevel: log.InfoLevel,
			},
			wantErr: false,
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_time.yaml"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_remedy.yaml"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := os.Open(tt.args.configPath)
			if err != nil {
				t.Errorf("Open() error = %+v", err)
				return
			}
			got, err := NewConfig(reader)
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
