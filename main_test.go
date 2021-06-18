package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

func Test_loadCachedStates(t *testing.T) {
	type args struct {
		dataPath       string
		expectedStates []*CloudflareState
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "simple load cache",
			args: args{dataPath: "./test_data/test_cache.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cachePath = tt.args.dataPath
			states := make([]CloudflareState, 0)
			if err := loadCachedStates(&states); err != nil {
				t.Error(err)
			}
			ti, _ := time.Parse(time.RFC3339, "2021-06-17T12:40:19Z")

			expectedStates := []CloudflareState{
				{
					Action:    "challenge",
					AccountID: "9d0c7e0dda3282e19d0e168f776cbe99",
					FilterIDByZoneID: map[string]string{
						"a07cf64479c4f2606834f073ac1a671b": "d1113e33000c452e9b53a209d378652d",
					},
					CurrExpr: "(ip.src in $crowdsec_challenge)",
					IPListState: IPListState{
						IPList: &cloudflare.IPList{
							ID:                    "28a7b38abd444721aa1cd74c261036e8",
							Name:                  "crowdsec_challenge",
							Description:           "challenge IP list by crowdsec",
							Kind:                  "ip",
							NumItems:              0,
							NumReferencingFilters: 0,
							CreatedOn:             &ti,
							ModifiedOn:            &ti,
						},
						ItemByIP: make(map[string]cloudflare.IPListItem),
					},
					CountrySet:          make(map[string]struct{}),
					AutonomousSystemSet: make(map[string]struct{}),
				},
			}
			if !reflect.DeepEqual(expectedStates, states) {
				t.Errorf("expected=%+v, \n found=%+v", expectedStates[0].IPListState.IPList, states[0].IPListState.IPList)
			}

		})
	}
}
