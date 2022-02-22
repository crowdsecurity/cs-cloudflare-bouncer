package main

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

var mockAPICallCounter uint32 = 0

type mockCloudflareAPI struct {
	IPLists           []cloudflare.IPList
	FirewallRulesList []cloudflare.FirewallRule
	FilterList        []cloudflare.Filter
	IPListItems       map[string][]cloudflare.IPListItem
	ZoneList          []cloudflare.Zone
}

func (cfAPI *mockCloudflareAPI) Filters(ctx context.Context, zoneID string, pageOpts cloudflare.PaginationOptions) ([]cloudflare.Filter, error) {
	return cfAPI.FilterList, nil
}

func (cfAPI *mockCloudflareAPI) ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error) {
	return cfAPI.ZoneList, nil
}

func (cfAPI *mockCloudflareAPI) CreateIPList(ctx context.Context, name string, desc string, typ string) (cloudflare.IPList, error) {
	ipList := cloudflare.IPList{ID: strconv.Itoa(len(cfAPI.IPLists))}
	cfAPI.IPLists = append(cfAPI.IPLists, ipList)
	return ipList, nil
}

func (cfAPI *mockCloudflareAPI) DeleteIPList(ctx context.Context, id string) (cloudflare.IPListDeleteResponse, error) {
	for i, j := range cfAPI.IPLists {
		if j.ID == id {
			cfAPI.IPLists = append(cfAPI.IPLists[:i], cfAPI.IPLists[i+1:]...)
			break
		}
	}
	return cloudflare.IPListDeleteResponse{}, nil
}

func (cfAPI *mockCloudflareAPI) ListIPLists(ctx context.Context) ([]cloudflare.IPList, error) {
	return cfAPI.IPLists, nil
}

func (cfAPI *mockCloudflareAPI) CreateFirewallRules(ctx context.Context, zone string, rules []cloudflare.FirewallRule) ([]cloudflare.FirewallRule, error) {
	cfAPI.FirewallRulesList = append(cfAPI.FirewallRulesList, rules...)
	for i := range cfAPI.FirewallRulesList {
		cfAPI.FirewallRulesList[i].ID = strconv.Itoa(i)
		cfAPI.FirewallRulesList[i].Filter.ID = strconv.Itoa(i)
	}
	return rules, nil
}
func (cfAPI *mockCloudflareAPI) DeleteFirewallRule(ctx context.Context, zone string, id string) error {
	for i, j := range cfAPI.FirewallRulesList {
		if j.ID == id {
			cfAPI.FirewallRulesList = append(cfAPI.FirewallRulesList[:i], cfAPI.FirewallRulesList[i+1:]...)
			break
		}
	}
	return nil
}
func (cfAPI *mockCloudflareAPI) DeleteFirewallRules(ctx context.Context, zoneID string, firewallRuleIDs []string) error {
	for _, rule := range firewallRuleIDs {
		cfAPI.DeleteFirewallRule(ctx, zoneID, rule)
	}
	return nil
}
func (cfAPI *mockCloudflareAPI) DeleteFilter(ctx context.Context, zone string, id string) error {
	for i, j := range cfAPI.FilterList {
		if j.ID == id {
			cfAPI.FilterList = append(cfAPI.FilterList[:i], cfAPI.FilterList[i+1:]...)
			break
		}
	}
	return nil
}

func (cfAPI *mockCloudflareAPI) DeleteFilters(ctx context.Context, zoneID string, filterIDs []string) error {
	for _, filterId := range filterIDs {
		cfAPI.DeleteFilter(ctx, zoneID, filterId)
	}
	return nil
}

func (cfAPI *mockCloudflareAPI) DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error) {
	for j := range cfAPI.IPLists {
		if cfAPI.IPLists[j].ID == id {
			cfAPI.IPLists[j].NumItems -= len(items.Items)
			break
		}
	}
	rm := make([]bool, len(cfAPI.IPListItems[id]))
	for _, item := range items.Items {
		for j, currItem := range cfAPI.IPListItems[id] {
			if currItem.ID == item.ID {
				rm[j] = true
			}
		}
	}
	newItems := make([]cloudflare.IPListItem, 0)
	for i, item := range cfAPI.IPListItems[id] {
		if !rm[i] {
			newItems = append(newItems, item)
		}
	}
	cfAPI.IPListItems[id] = newItems
	return cfAPI.IPListItems[id], nil
}

func (cfAPI *mockCloudflareAPI) ListIPListItems(ctx context.Context, id string) ([]cloudflare.IPListItem, error) {
	return []cloudflare.IPListItem{
		{ID: "1234"},
	}, nil
}

func (cfAPI *mockCloudflareAPI) UpdateFilters(ctx context.Context, zoneID string, filters []cloudflare.Filter) ([]cloudflare.Filter, error) {
	for _, f := range filters {
		for j := range cfAPI.FilterList {
			if cfAPI.FilterList[j].ID == f.ID {
				cfAPI.FilterList[j] = f
			}
		}
	}
	return cfAPI.FilterList, nil
}

func (cfAPI *mockCloudflareAPI) FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error) {
	return cfAPI.FirewallRulesList, nil
}

func (cfAPI *mockCloudflareAPI) GetIPListBulkOperation(ctx context.Context, id string) (cloudflare.IPListBulkOperation, error) {
	return cloudflare.IPListBulkOperation{Status: "completed"}, nil
}

func (cfAPI *mockCloudflareAPI) ReplaceIPListItemsAsync(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) (cloudflare.IPListItemCreateResponse, error) {
	IPItems := make([]cloudflare.IPListItem, len(items))
	for j := range cfAPI.IPLists {
		if cfAPI.IPLists[j].ID == id {
			cfAPI.IPLists[j].NumItems += len(items)
			break
		}
	}
	for i := range items {
		IPItems[i] = cloudflare.IPListItem{IP: items[i].IP}
	}
	cfAPI.IPListItems[id] = IPItems
	return cloudflare.IPListItemCreateResponse{}, nil
}

var dummyCFAccount AccountConfig = AccountConfig{
	ID: "dummyID",
	ZoneConfigs: []ZoneConfig{
		{
			ID:      "zone1",
			Actions: []string{"block"},
		},
	},
	IPListPrefix:  "crowdsec",
	DefaultAction: "block",
}

var mockCfAPI cloudflareAPI = &mockCloudflareAPI{
	IPLists: []cloudflare.IPList{{ID: "11", Name: "crowdsec_block", Description: "already"}, {ID: "12", Name: "crowd"}},
	FirewallRulesList: []cloudflare.FirewallRule{
		{Filter: cloudflare.Filter{Expression: "ip in $crowdsec_block"}},
		{Filter: cloudflare.Filter{Expression: "ip in $dummy"}}},
	ZoneList: []cloudflare.Zone{
		{ID: "zone1"},
	},
	IPListItems: make(map[string][]cloudflare.IPListItem),
}

func TestIPFirewallSetUp(t *testing.T) {

	ctx := context.Background()
	wg := sync.WaitGroup{}
	wg.Add(1)
	worker := CloudflareWorker{
		API:            mockCfAPI,
		Account:        dummyCFAccount,
		Wg:             &wg,
		UpdatedState:   make(chan map[string]*CloudflareState, 2),
		Count:          prometheus.NewCounter(prometheus.CounterOpts{}),
		tokenCallCount: &mockAPICallCounter,
	}
	worker.Init()
	worker.SetUpCloudflareIfNewState()
	ipLists, err := mockCfAPI.ListIPLists(ctx)

	if err != nil {
		t.Error(err)
	}
	if len(ipLists) != 2 {
		t.Errorf("expected only 2 IP list found %d", len(ipLists))
	}

	if ipLists[1].Description != "" {
		t.Error("old iplist exists")
	}

	fr, err := mockCfAPI.FirewallRules(ctx, "", cloudflare.PaginationOptions{})
	if err != nil {
		t.Error(err)
	}
	if len(fr) != 2 {
		t.Errorf("expected only 2 firewall rule  found %d", len(fr))
	}
}

func TestCollectLAPIStream(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	ip1 := "1.2.3.4"
	ip2 := "1.2.3.5"
	scope := "ip"
	a := "ban"

	addedDecisions := &models.Decision{Value: &ip1, Scope: &scope, Type: &a}
	deletedDecisions := &models.Decision{Value: &ip2, Scope: &scope, Type: &a}

	dummyResponse := &models.DecisionsStreamResponse{
		New:     []*models.Decision{addedDecisions},
		Deleted: []*models.Decision{deletedDecisions},
	}
	worker := CloudflareWorker{
		Account:        dummyCFAccount,
		API:            mockCfAPI,
		Wg:             &wg,
		UpdatedState:   make(chan map[string]*CloudflareState, 1),
		Count:          prometheus.NewCounter(prometheus.CounterOpts{}),
		tokenCallCount: &mockAPICallCounter,
	}
	worker.Init()
	worker.setUpIPList()

	worker.CollectLAPIStream(dummyResponse)
	if len(worker.NewIPDecisions) != 1 {
		t.Errorf("expected 1 key in 'NewIPSet' but found %d", len(worker.NewIPDecisions))
	}

	if len(worker.ExpiredIPDecisions) != 1 {
		t.Errorf("expected 1 key in 'ExpiredIPSet' but found %d", len(worker.ExpiredIPDecisions))
	}
}

func Test_setToExprList(t *testing.T) {
	type args struct {
		set    map[string]struct{}
		quotes bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "unquoted",
			args: args{
				set: map[string]struct{}{
					"1.2.3.4": {},
					"6.7.8.9": {},
				},
				quotes: false,
			},
			want: `{1.2.3.4 6.7.8.9}`,
		},
		{
			name: "quoted",
			args: args{
				set: map[string]struct{}{
					"US": {},
					"UK": {},
				},
				quotes: true,
			},
			want: `{"UK" "US"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := setToExprList(tt.args.set, tt.args.quotes); got != tt.want {
				t.Errorf("setToExprList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudflareState_computeExpression(t *testing.T) {
	type fields struct {
		ipListState         IPListState
		countrySet          map[string]struct{}
		autonomousSystemSet map[string]struct{}
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "all null",
			fields: fields{},
			want:   "",
		},
		{
			name: "only country",
			fields: fields{countrySet: map[string]struct{}{
				"US": {},
				"UK": {},
			}},
			want: `(ip.geoip.country in {"UK" "US"})`,
		},
		{
			name:   "only ip list",
			fields: fields{ipListState: IPListState{IPList: &cloudflare.IPList{Name: "crowdsec_block"}}},
			want:   `(ip.src in $crowdsec_block)`,
		},
		{
			name: "ip list + as ban",
			fields: fields{
				ipListState:         IPListState{IPList: &cloudflare.IPList{Name: "crowdsec_block"}},
				autonomousSystemSet: map[string]struct{}{"1234": {}, "5432": {}},
			},
			want: `(ip.geoip.asnum in {1234 5432}) or (ip.src in $crowdsec_block)`,
		},
		{
			name: "ip list + as ban + country",
			fields: fields{
				ipListState:         IPListState{IPList: &cloudflare.IPList{Name: "crowdsec_block"}},
				autonomousSystemSet: map[string]struct{}{"1234": {}, "5432": {}},
				countrySet:          map[string]struct{}{"US": {}, "UK": {}},
			},
			want: `(ip.geoip.country in {"UK" "US"}) or (ip.geoip.asnum in {1234 5432}) or (ip.src in $crowdsec_block)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfState := &CloudflareState{
				IPListState:         tt.fields.ipListState,
				CountrySet:          tt.fields.countrySet,
				AutonomousSystemSet: tt.fields.autonomousSystemSet,
			}
			if got := cfState.computeExpression(); got != tt.want {
				t.Errorf("CloudflareState.computeExpression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_classifyDecisionsByAction(t *testing.T) {
	ip1 := "1.2.3.4"
	ip2 := "1.2.3.5"

	captcha := "captcha"
	ban := "ban"
	random := "random"

	decision1 := models.Decision{Value: &ip1, Type: &ban}
	decision2 := models.Decision{Value: &ip2, Type: &captcha}
	decision2dup := models.Decision{Value: &ip2, Type: &ban}
	decisionUnsup := models.Decision{Value: &ip2, Type: &random}

	type args struct {
		decisions []*models.Decision
	}
	tests := []struct {
		name string
		args args
		want map[string][]*models.Decision
	}{
		{
			name: "all supported, no dups",
			args: args{decisions: []*models.Decision{&decision1, &decision2}},
			want: map[string][]*models.Decision{
				"defaulted": {},
				"block": {
					&decision1,
				},
				"challenge": {
					&decision2,
				},
			},
		},
		{
			name: "with dups, all supported",
			args: args{decisions: []*models.Decision{&decision2, &decision2dup}},
			want: map[string][]*models.Decision{
				"defaulted": {},
				"challenge": {&decision2},
			},
		},
		{
			name: "unsupported, no dups",
			args: args{decisions: []*models.Decision{&decision1, &decisionUnsup}},
			want: map[string][]*models.Decision{
				"defaulted": {
					&decisionUnsup,
				},
				"block": {
					&decision1,
				},
			},
		},
		{
			name: "unsupported with dups",
			args: args{
				decisions: []*models.Decision{&decisionUnsup, &decision1, &decision2},
			},
			want: map[string][]*models.Decision{
				"defaulted": {},
				"block":     {&decision1},
				"challenge": {&decision2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dedupAndClassifyDecisionsByAction(tt.args.decisions); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("classifyDecisionsByAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_normalizeIP(t *testing.T) {
	type args struct {
		ip string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "simple ipv4",
			args: args{
				ip: "1.2.3.4",
			},
			want: "1.2.3.4",
		},
		{
			name: "full ipv6 must be shortened to /64 form",
			args: args{
				ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			},
			want: "2001:db8:85a3::/64",
		},
		{
			name: "full ipv6 in shortform must be converted to subnet form",
			args: args{
				ip: "2001::",
			},
			want: "2001::/64",
		},
		{
			name: "full ipv6 with cidr should be made to atlease /64 form",
			args: args{
				ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/65",
			},
			want: "2001:db8:85a3::/64",
		},
		{
			name: "ipv6 shortform, but has valid tail",
			args: args{
				ip: "2600:3c02::f03c:92ff:fe65:f0ff", // 2600:3c02:0000:0000:f03c:92ff:fe65:f0ff
			},
			want: "2600:3c02::/64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDecisionValue(tt.args.ip); got != tt.want {
				t.Errorf("normalizeIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudflareWorker_SendASBans(t *testing.T) {
	ASNum1 := "1234"
	ASNum2 := "1235"

	action := "block"
	unSupAction := "toto"

	type fields struct {
		CFStateByAction map[string]*CloudflareState
		NewASDecisions  []*models.Decision
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "simple supported decision",
			fields: fields{
				NewASDecisions: []*models.Decision{{Value: &ASNum1, Type: &action}},
			},
			want: []string{"1234"},
		},
		{
			name: "simple supported multiple decisions without duplicates",
			fields: fields{
				NewASDecisions: []*models.Decision{
					{Value: &ASNum1, Type: &action},
					{Value: &ASNum2, Type: &action},
				},
			},
			want: []string{"1234", "1235"},
		},
		{
			name: "unsupported decision should be defaulted ",
			fields: fields{
				NewASDecisions: []*models.Decision{
					{Value: &ASNum1, Type: &unSupAction},
				},
			},
			want: []string{"1234"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				CFStateByAction: tt.fields.CFStateByAction,
				NewASDecisions:  tt.fields.NewASDecisions,
				Logger:          log.WithFields(log.Fields{"account_id": "test worker"}),
				tokenCallCount:  &mockAPICallCounter,
			}
			worker.CFStateByAction = make(map[string]*CloudflareState)
			worker.Account = dummyCFAccount
			worker.CFStateByAction[action] = &CloudflareState{AutonomousSystemSet: make(map[string]struct{})}
			err := worker.SendASBans()
			if err != nil {
				t.Error(err)
			}
			found := make([]string, 0)
			for f := range worker.CFStateByAction[action].AutonomousSystemSet {
				found = append(found, f)
			}
			sort.Strings(found)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(found, tt.want) {
				t.Errorf("expected=%v found=%v ", tt.want, found)
			}

		})
	}
}

func TestCloudflareWorker_DeleteASBans(t *testing.T) {
	ASNum1 := "1234"
	// ASNum2 := "1235"

	action := "block"
	// unSupAction := "toto"

	type fields struct {
		CFStateByAction    map[string]*CloudflareState
		ExpiredASDecisions []*models.Decision
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "simple delete AS",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						AutonomousSystemSet: map[string]struct{}{"1234": {}, "1236": {}},
					},
				},
				ExpiredASDecisions: []*models.Decision{{Value: &ASNum1, Type: &action}},
			},
			want: []string{"1236"},
		},
		{
			name: "delete something that does not exist",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						AutonomousSystemSet: map[string]struct{}{"1235": {}},
					},
				},
				ExpiredASDecisions: []*models.Decision{{Value: &ASNum1, Type: &action}},
			},
			want: []string{"1235"},
		},
		{
			name: "delete something multiple times",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						AutonomousSystemSet: map[string]struct{}{"1234": {}, "9999": {}},
					},
				},
				ExpiredASDecisions: []*models.Decision{{Value: &ASNum1, Type: &action}, {Value: &ASNum1, Type: &action}, {Value: &ASNum1, Type: &action}},
			},
			want: []string{"9999"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				CFStateByAction:    tt.fields.CFStateByAction,
				ExpiredASDecisions: tt.fields.ExpiredASDecisions,
				Logger:             log.WithFields(log.Fields{"account_id": "test worker"}),
				tokenCallCount:     &mockAPICallCounter,
			}
			worker.Account = dummyCFAccount
			err := worker.DeleteASBans()
			if err != nil {
				t.Error(err)
			}
			found := make([]string, 0)
			for f := range worker.CFStateByAction[action].AutonomousSystemSet {
				found = append(found, f)
			}
			sort.Strings(found)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(found, tt.want) {
				t.Errorf("expected=%v found=%v ", tt.want, found)
			}

		})
	}
}

func TestCloudflareWorker_SendCountryBans(t *testing.T) {
	Country1 := "IN"
	Country2 := "CH"

	action := "block"
	unSupAction := "toto"

	type fields struct {
		CFStateByAction     map[string]*CloudflareState
		NewCountryDecisions []*models.Decision
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "simple supported decision",
			fields: fields{
				NewCountryDecisions: []*models.Decision{{Value: &Country1, Type: &action}},
			},
			want: []string{"IN"},
		},
		{
			name: "simple supported multiple decisions without duplicates",
			fields: fields{
				NewCountryDecisions: []*models.Decision{
					{Value: &Country1, Type: &action},
					{Value: &Country2, Type: &action},
				},
			},
			want: []string{"IN", "CH"},
		},
		{
			name: "unsupported decision should be defaulted ",
			fields: fields{
				NewCountryDecisions: []*models.Decision{
					{Value: &Country1, Type: &unSupAction},
				},
			},
			want: []string{"IN"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				CFStateByAction:     tt.fields.CFStateByAction,
				NewCountryDecisions: tt.fields.NewCountryDecisions,
				Logger:              log.WithFields(log.Fields{"account_id": "test worker"}),
				tokenCallCount:      &mockAPICallCounter,
			}
			worker.CFStateByAction = make(map[string]*CloudflareState)
			worker.Account = dummyCFAccount
			worker.CFStateByAction[action] = &CloudflareState{CountrySet: make(map[string]struct{})}
			err := worker.SendCountryBans()
			if err != nil {
				t.Error(err)
			}
			found := make([]string, 0)
			for f := range worker.CFStateByAction[action].CountrySet {
				found = append(found, f)
			}
			sort.Strings(found)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(found, tt.want) {
				t.Errorf("expected=%v found=%v ", tt.want, found)
			}

		})
	}
}

func TestCloudflareWorker_DeleteCountryBans(t *testing.T) {
	Country1 := "UK"
	action := "block"

	type fields struct {
		CFStateByAction         map[string]*CloudflareState
		ExpiredCountryDecisions []*models.Decision
	}
	tests := []struct {
		name   string
		fields fields
		want   []string
	}{
		{
			name: "simple delete AS",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						CountrySet: map[string]struct{}{"UK": {}, "1236": {}},
					},
				},
				ExpiredCountryDecisions: []*models.Decision{{Value: &Country1, Type: &action}},
			},
			want: []string{"1236"},
		},
		{
			name: "delete something that does not exist",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						CountrySet: map[string]struct{}{"1235": {}},
					},
				},
				ExpiredCountryDecisions: []*models.Decision{{Value: &Country1, Type: &action}},
			},
			want: []string{"1235"},
		},
		{
			name: "delete something multiple times",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						CountrySet: map[string]struct{}{"UK": {}, "9999": {}},
					},
				},
				ExpiredCountryDecisions: []*models.Decision{{Value: &Country1, Type: &action}, {Value: &Country1, Type: &action}, {Value: &Country1, Type: &action}},
			},
			want: []string{"9999"},
		},
		{
			name: "ipv6 dups",
			fields: fields{
				CFStateByAction: map[string]*CloudflareState{
					action: {
						CountrySet: map[string]struct{}{"UK": {}, "9999": {}},
					},
				},
				ExpiredCountryDecisions: []*models.Decision{{Value: &Country1, Type: &action}, {Value: &Country1, Type: &action}, {Value: &Country1, Type: &action}},
			},
			want: []string{"9999"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				CFStateByAction:         tt.fields.CFStateByAction,
				ExpiredCountryDecisions: tt.fields.ExpiredCountryDecisions,
				Logger:                  log.WithFields(log.Fields{"account_id": "test worker"}),
				tokenCallCount:          &mockAPICallCounter,
			}
			worker.Account = dummyCFAccount
			err := worker.DeleteCountryBans()
			if err != nil {
				t.Error(err)
			}
			found := make([]string, 0)
			for f := range worker.CFStateByAction[action].CountrySet {
				found = append(found, f)
			}
			sort.Strings(found)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(found, tt.want) {
				t.Errorf("expected=%v found=%v ", tt.want, found)
			}

		})
	}
}

func Test_allZonesHaveAction(t *testing.T) {
	type args struct {
		zones  []ZoneConfig
		action string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "true",
			args: args{
				zones: []ZoneConfig{
					{
						ActionSet: map[string]struct{}{
							"block": {},
						},
					},
					{
						ActionSet: map[string]struct{}{
							"block": {},
						},
					},
				},
				action: "block",
			},
			want: true,
		},
		{
			name: "false",
			args: args{
				zones: []ZoneConfig{
					{
						ActionSet: map[string]struct{}{
							"challenge": {},
						},
					},
					{
						ActionSet: map[string]struct{}{
							"block": {},
						},
					},
				},
				action: "block",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allZonesHaveAction(tt.args.zones, tt.args.action); got != tt.want {
				t.Errorf("allZonesHaveAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudflareWorker_AddNewIPs(t *testing.T) {
	// decision fixture
	ip1 := "1.2.3.4"
	action := "ban"
	scenario := "crowdsec/demo"
	randomAction := "foo"

	state := map[string]*CloudflareState{
		"block": {
			AccountID: dummyCFAccount.ID,
			IPListState: IPListState{
				IPSet:  make(map[string]IPSetItem),
				IPList: &cloudflare.IPList{},
			},
		},
	}

	type fields struct {
		Account         AccountConfig
		CFStateByAction map[string]*CloudflareState
		NewIPDecisions  []*models.Decision
		API             cloudflareAPI
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]IPSetItem
	}{
		{
			name: "supported ip decision",
			fields: fields{
				Account:         dummyCFAccount,
				CFStateByAction: state,
				NewIPDecisions: []*models.Decision{
					{Value: &ip1, Type: &action, Scenario: &scenario},
				},
				API: mockCfAPI,
			},
			want: map[string]IPSetItem{
				"1.2.3.4": {},
			},
		},
		{
			name: "unsupported ip decision",
			fields: fields{
				Account:         dummyCFAccount,
				CFStateByAction: state,
				NewIPDecisions: []*models.Decision{
					{Value: &ip1, Type: &randomAction, Scenario: &scenario},
				},
				API: mockCfAPI,
			},
			want: map[string]IPSetItem{
				"1.2.3.4": {},
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				Account:         tt.fields.Account,
				CFStateByAction: tt.fields.CFStateByAction,
				NewIPDecisions:  tt.fields.NewIPDecisions,
				API:             mockCfAPI,
				Logger:          log.WithFields(log.Fields{"account_id": "test worker"}),
				Count:           promauto.NewCounter(prometheus.CounterOpts{Name: fmt.Sprintf("test%d", i), Help: "no help you're just a test"}),
				tokenCallCount:  &mockAPICallCounter,
				UpdatedState:    make(chan map[string]*CloudflareState, 100),
			}
			err := worker.UpdateIPLists()
			if err != nil {
				t.Error(err)
			}
			if !IPSetsAreEqual(tt.want, worker.CFStateByAction["block"].IPListState.IPSet) {
				t.Errorf("want=%+v, found=%+v", tt.want, worker.CFStateByAction["block"].IPListState.IPSet)
			}
		})
	}
}

func TestCloudflareWorker_DeleteIPs(t *testing.T) {
	// decision fixture
	ip1 := "1.2.3.4"
	action := "ban"
	scenario := "crowdsec/demo"
	randomAction := "foo"

	state := map[string]*CloudflareState{
		"block": {
			AccountID: dummyCFAccount.ID,
			IPListState: IPListState{
				IPSet: map[string]IPSetItem{
					"1.2.3.4": {},
					"1.2.3.5": {},
				},
				IPList: &cloudflare.IPList{},
			},
		},
	}

	type fields struct {
		Account            AccountConfig
		CFStateByAction    map[string]*CloudflareState
		ExpiredIPDecisions []*models.Decision
		API                cloudflareAPI
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]IPSetItem
	}{
		{
			name: "supported ip decision",
			fields: fields{
				Account:         dummyCFAccount,
				CFStateByAction: state,
				ExpiredIPDecisions: []*models.Decision{
					{Value: &ip1, Type: &action, Scenario: &scenario},
				},
				API: mockCfAPI,
			},
			want: map[string]IPSetItem{
				"1.2.3.5": {},
			},
		},
		{
			name: "unsupported ip decision",
			fields: fields{
				Account:         dummyCFAccount,
				CFStateByAction: state,
				ExpiredIPDecisions: []*models.Decision{
					{Value: &ip1, Type: &randomAction, Scenario: &scenario},
				},
				API: mockCfAPI,
			},
			want: map[string]IPSetItem{
				"1.2.3.5": {},
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				Account:            tt.fields.Account,
				CFStateByAction:    tt.fields.CFStateByAction,
				ExpiredIPDecisions: tt.fields.ExpiredIPDecisions,
				API:                mockCfAPI,
				Logger:             log.WithFields(log.Fields{"account_id": "test worker"}),
				Count:              promauto.NewCounter(prometheus.CounterOpts{Name: fmt.Sprintf("test2%d", i), Help: "no help you're just a test"}),
				tokenCallCount:     &mockAPICallCounter,
				UpdatedState:       make(chan map[string]*CloudflareState, 100),
			}
			err := worker.UpdateIPLists()
			if err != nil {
				t.Error(err)
			}
			if !IPSetsAreEqual(tt.want, worker.CFStateByAction["block"].IPListState.IPSet) {
				t.Errorf("want=%+v, found=%+v", tt.want, worker.CFStateByAction["block"].IPListState.IPSet)
			}
		})
	}
}

func timeForMonth(month time.Month) time.Time {
	return time.Date(2000, month, 1, 1, 1, 1, 1, time.UTC)
}

func Test_keepLatestNIPSetItems(t *testing.T) {
	type args struct {
		set map[string]IPSetItem
		n   int
	}
	tests := []struct {
		name string
		args args
		want map[string]IPSetItem
	}{
		{
			name: "regular",
			args: args{
				set: map[string]IPSetItem{
					"1.2.3.5": {CreatedAt: timeForMonth(time.May)},
					"1.2.3.4": {CreatedAt: timeForMonth(time.April)},
					"1.2.3.6": {CreatedAt: timeForMonth(time.March)},
				},
				n: 2,
			},
			want: map[string]IPSetItem{
				"1.2.3.5": {CreatedAt: timeForMonth(time.May)},
				"1.2.3.4": {CreatedAt: timeForMonth(time.April)},
			},
		},
		{
			name: "no items to drop",
			args: args{
				set: map[string]IPSetItem{
					"1.2.3.5": {CreatedAt: timeForMonth(time.May)},
					"1.2.3.4": {CreatedAt: timeForMonth(time.April)},
					"1.2.3.6": {CreatedAt: timeForMonth(time.March)},
				},
				n: 3,
			},
			want: map[string]IPSetItem{
				"1.2.3.5": {CreatedAt: timeForMonth(time.May)},
				"1.2.3.4": {CreatedAt: timeForMonth(time.April)},
				"1.2.3.6": {CreatedAt: timeForMonth(time.March)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := keepLatestNIPSetItems(tt.args.set, tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keepLatestNIPSetItems() = %v, want %v", got, tt.want)
			}
		})
	}
}

func IPSetsAreEqual(a map[string]IPSetItem, b map[string]IPSetItem) bool {
	aOnly, bOnly := calculateIPSetDiff(a, b)
	return aOnly == 0 && bOnly == 0
}
