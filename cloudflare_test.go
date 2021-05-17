package main

import (
	"context"
	"log"
	"testing"

	"github.com/cloudflare/cloudflare-go"
)

type mockCloudflareAPI struct {
	IPLists           []cloudflare.IPList
	FirewallRulesList []cloudflare.FirewallRule
	FilterList        []cloudflare.Filter
	IPListItems       map[string][]cloudflare.IPListItem
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

func (cfAPI *mockCloudflareAPI) DeleteFilter(ctx context.Context, zone string, id string) error {
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
	conf, err := NewConfig("./test_data/valid_config.yaml")

	if err != nil {
		t.Errorf("failure in  loading config %s", err.Error())
	}

	setUpIPListAndFirewall(ctx, mockCfAPI, conf)
	ipLists, err := mockCfAPI.ListIPLists(ctx)

	if err != nil {
		log.Fatal(err)
	}
	if len(ipLists) != 2 {
		t.Errorf("expected only 2 IP list found %d", len(ipLists))
	}

	fr, err := mockCfAPI.FirewallRules(ctx, "", cloudflare.PaginationOptions{})
	if err != nil {
		log.Fatal(err)
	}
	if len(fr) != 2 {
		t.Errorf("expected only 1 firewall rule  found %d", len(fr))
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
