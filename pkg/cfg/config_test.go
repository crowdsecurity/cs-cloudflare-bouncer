package cfg

import (
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"
)

func TestNewConfig(t *testing.T) {
	type args struct {
		configPath string
	}
	tests := []struct {
		name    string
		args    args
		want    *bouncerConfig
		wantErr string
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
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_time.yaml"},
			wantErr: "failed to unmarshal: yaml: unmarshal errors:\n  line 18: cannot unmarshal !!str `blah` into time.Duration",
		},
		{
			name:    "invalid time",
			args:    args{"./testdata/invalid_config_remedy.yaml"},
			wantErr: "zone test doesn't support the default action challenge for it's account",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := os.Open(tt.args.configPath)
			require.NoError(t, err)
			got, err := NewConfig(reader)
			cstest.RequireErrorContains(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
}
