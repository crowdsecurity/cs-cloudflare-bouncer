package main

import (
	"context"
	"strconv"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

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

var dummyCFAccount CloudflareAccount = CloudflareAccount{
	ID: "dummyID",
	Zones: []CloudflareZone{
		{
			ID:          "zone1",
			Remediation: []string{"block"},
		},
	},
	IPListPrefix: "crowdsec",
}

var mockCfAPI cloudflareAPI = &mockCloudflareAPI{
	IPLists: []cloudflare.IPList{{ID: "11", Name: "crowdsec_block", Description: "already"}, {ID: "12", Name: "crowd"}},
	FirewallRulesList: []cloudflare.FirewallRule{
		{Filter: cloudflare.Filter{Expression: "ip in $crowdsec"}},
		{Filter: cloudflare.Filter{Expression: "ip in $dummy"}}},
	ZoneList: []cloudflare.Zone{
		{ID: "zone1"},
	},
}

func TestIPFirewallSetUp(t *testing.T) {

	ctx := context.Background()
	worker := CloudflareWorker{
		API:     mockCfAPI,
		Account: dummyCFAccount,
	}
	worker.Init()

	worker.setUpIPList()
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
		t.Errorf("expected only 1 firewall rule  found %d", len(fr))
	}
}

func TestCollectLAPIStream(t *testing.T) {
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
	worker := CloudflareWorker{Account: dummyCFAccount, API: mockCfAPI}
	worker.Init()
	worker.setUpIPList()

	worker.CollectLAPIStream(dummyResponse)
	if len(worker.NewIPSet["block"]) != 1 {
		t.Errorf("expected 1 key in 'NewIPSet' but found %d", len(worker.NewIPSet["block"]))
	}

	if len(worker.ExpiredIPSet["block"]) != 1 {
		t.Errorf("expected 1 key in 'ExpiredIPSet' but found %d", len(worker.ExpiredIPSet["block"]))
	}
}
