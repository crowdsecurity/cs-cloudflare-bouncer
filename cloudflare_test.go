package main

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

type mockCloudflareAPI struct {
	IPLists           []cloudflare.IPList
	FirewallRulesList []cloudflare.FirewallRule
	FilterList        []cloudflare.Filter
	IPListItems       map[string][]cloudflare.IPListItem
}

func (cfAPI *mockCloudflareAPI) Filters(ctx context.Context, zoneID string, pageOpts cloudflare.PaginationOptions) ([]cloudflare.Filter, error) {
	return cfAPI.FilterList, nil
}

func (cfAPI *mockCloudflareAPI) ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error) {
	return make([]cloudflare.Zone, 0), nil
}

func (cfAPI *mockCloudflareAPI) CreateIPList(ctx context.Context, name string, desc string, typ string) (cloudflare.IPList, error) {
	ipList := cloudflare.IPList{ID: name}
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
	for i, _ := range cfAPI.FirewallRulesList {
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

func (cfAPI *mockCloudflareAPI) FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error) {
	return cfAPI.FirewallRulesList, nil
}
func (cfAPI *mockCloudflareAPI) CreateIPListItems(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) ([]cloudflare.IPListItem, error) {
	ips := make([]cloudflare.IPListItem, len(items))
	for i, _ := range items {
		ips[i] = cloudflare.IPListItem{IP: items[i].IP}
	}

	cfAPI.IPListItems[id] = append(cfAPI.IPListItems[id], ips...)

	return cfAPI.IPListItems[id], nil
}
func (cfAPI *mockCloudflareAPI) DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error) {

	return make([]cloudflare.IPListItem, 0), nil
}

func TestIPFirewallSetUp(t *testing.T) {

	var mockCfAPI cloudflareAPI = &mockCloudflareAPI{
		IPLists: []cloudflare.IPList{{ID: "11", Name: "crowdsec"}, {ID: "12", Name: "crowd"}},
		FirewallRulesList: []cloudflare.FirewallRule{
			{Filter: cloudflare.Filter{Expression: "ip in $crowdsec"}},
			{Filter: cloudflare.Filter{Expression: "ip in $dummy"}}}}

	ctx := context.Background()
	worker := CloudflareWorker{API: mockCfAPI, IPListName: "crowdsec"}
	worker.Init()

	worker.setUpIPList()
	ipLists, err := mockCfAPI.ListIPLists(ctx)

	if err != nil {
		t.Error(err)
	}
	if len(ipLists) != 2 {
		fmt.Printf("%+v\n", worker)
		t.Errorf("expected only 2 IP list found %d", len(ipLists))
	}

	fr, err := mockCfAPI.FirewallRules(ctx, "", cloudflare.PaginationOptions{})
	if err != nil {
		t.Error(err)
	}
	if len(fr) != 2 {
		t.Errorf("expected only 1 firewall rule  found %d", len(fr))
	}
}

func TestCollectLAPIStream(t *testing.T) {
	ip1 := "1.2.3.4"
	ip2 := "1.2.3.5"
	scope := "ip"
	addedDecisions := &models.Decision{Value: &ip1, Scope: &scope}
	deletedDecisions := &models.Decision{Value: &ip2, Scope: &scope}
	dummyResponse := &models.DecisionsStreamResponse{
		New:     []*models.Decision{addedDecisions},
		Deleted: []*models.Decision{deletedDecisions},
	}

	worker := CloudflareWorker{}
	worker.Init()
	worker.CloudflareIDByIP["1.2.3.5"] = "abcd"
	worker.CloudflareIDByIP["1.2.3.6"] = "abcd"

	worker.CollectLAPIStream(dummyResponse)

	if len(worker.CloudflareIDByIP) != 2 {
		t.Errorf("expected 1 key in 'CloudflareIDByIP' but found %d", len(worker.CloudflareIDByIP))
	}

	if len(worker.DeleteIPMap) != 1 {
		t.Errorf("expected 1 key in 'DeleteIPMap' but found %d", len(worker.DeleteIPMap))
	}

	if len(worker.AddIPMap) != 1 {
		t.Errorf("expected 1 key in 'AddIPMap' but found %d", len(worker.AddIPMap))
	}
}

func TestHelpers(t *testing.T) {
	addIPMap := map[cloudflare.IPListItemCreateRequest]bool{
		cloudflare.IPListItemCreateRequest{IP: "1.2.3.4"}: true,
		cloudflare.IPListItemCreateRequest{IP: "1.2.3.4"}: true,
		cloudflare.IPListItemCreateRequest{IP: "1.2.3.5"}: true,
	}
	addIPSlice := mapToSliceCreateRequest(addIPMap)
	if len(addIPSlice) != 2 {
		t.Errorf("expected 2 items in slice instead got %d", len(addIPSlice))
	}

	deleteIPMap := map[cloudflare.IPListItemDeleteItemRequest]bool{
		cloudflare.IPListItemDeleteItemRequest{ID: "1"}: true,
		cloudflare.IPListItemDeleteItemRequest{ID: "2"}: true,
		cloudflare.IPListItemDeleteItemRequest{ID: "1"}: true,
	}
	deleteIPSlice := mapToSliceDeleteRequest(deleteIPMap)
	if len(deleteIPSlice) != 2 {
		t.Errorf("expected 2 items in slice instead got %d", len(deleteIPSlice))
	}

}

func TestCloudflareWorker_deleteRulesContainingString(t *testing.T) {
	type fields struct {
		Account           CloudflareAccount
		API               cloudflareAPI
	}
	type args struct {
		str      string
		zonesIDs []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			fields: fields{Account: CloudflareAccount{}},
		}	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := &CloudflareWorker{
				Logger:            tt.fields.Logger,
				Account:           tt.fields.Account,
				ZoneLocks:         tt.fields.ZoneLocks,
				Ctx:               tt.fields.Ctx,
				LAPIStream:        tt.fields.LAPIStream,
				IPListName:        tt.fields.IPListName,
				IPListID:          tt.fields.IPListID,
				UpdateFrequency:   tt.fields.UpdateFrequency,
				CloudflareIDByIP:  tt.fields.CloudflareIDByIP,
				DeleteIPMap:       tt.fields.DeleteIPMap,
				AddIPMap:          tt.fields.AddIPMap,
				AddASBans:         tt.fields.AddASBans,
				RemoveASBans:      tt.fields.RemoveASBans,
				AddCountryBans:    tt.fields.AddCountryBans,
				RemoveCountryBans: tt.fields.RemoveCountryBans,
				API:               tt.fields.API,
			}
			if err := worker.deleteRulesContainingString(tt.args.str, tt.args.zonesIDs); (err != nil) != tt.wantErr {
				t.Errorf("CloudflareWorker.deleteRulesContainingString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
