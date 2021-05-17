package main

import (
	"context"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/common/log"
)

type cloudflareAPI interface {
	CreateIPList(ctx context.Context, name string, desc string, typ string) (cloudflare.IPList, error)
	DeleteIPList(ctx context.Context, id string) (cloudflare.IPListDeleteResponse, error)
	ListIPLists(ctx context.Context) ([]cloudflare.IPList, error)
	CreateFirewallRules(ctx context.Context, zone string, rules []cloudflare.FirewallRule) ([]cloudflare.FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, zone string, id string) error
	DeleteFilter(ctx context.Context, zone string, id string) error
	FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error)
	CreateIPListItems(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) ([]cloudflare.IPListItem, error)
	DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error)
}

func deleteExistingCrowdSecIPList(ctx context.Context, cfAPI cloudflareAPI, conf *bouncerConfig) error {
	ipLists, err := cfAPI.ListIPLists(ctx)
	if err != nil {
		return err
	}

	id := getIPListID(ipLists, conf.CloudflareIPListName)
	if id == nil {
		return nil
	}

	err = removeIPListDependencies(ctx, cfAPI, conf)
	if err != nil {
		return err
	}

	_, err = cfAPI.DeleteIPList(ctx, *id)
	if err != nil {
		return err
	}
	return nil
}

func removeIPListDependencies(ctx context.Context, cfAPI cloudflareAPI, conf *bouncerConfig) error {
	rules, err := cfAPI.FirewallRules(ctx, conf.CloudflareZoneID, cloudflare.PaginationOptions{})
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if strings.Contains(rule.Filter.Expression, "$"+conf.CloudflareIPListName) {
			err := cfAPI.DeleteFirewallRule(ctx, conf.CloudflareZoneID, rule.ID)
			if err != nil {
				return err
			}

			err = cfAPI.DeleteFilter(ctx, conf.CloudflareZoneID, rule.Filter.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getIPListID(ipLists []cloudflare.IPList, IPListName string) *string {
	for _, ipList := range ipLists {
		if ipList.Name == IPListName {
			return &ipList.ID
		}
	}
	log.Infof("ip list %s does not exists", IPListName)
	return nil
}

func setUpIPListAndFirewall(ctx context.Context, cfAPI cloudflareAPI, conf *bouncerConfig) (string, error) {
	err := deleteExistingCrowdSecIPList(ctx, cfAPI, conf)
	if err != nil {
		return "", err
	}

	ipList, err := cfAPI.CreateIPList(ctx, "crowdsec", "IP list managed by crowdsec bouncer", "ip")
	if err != nil {
		return "", err
	}

	firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: "ip.src in $crowdsec"}, Action: conf.Action}}
	_, err = cfAPI.CreateFirewallRules(ctx, conf.CloudflareZoneID, firewallRules)
	if err != nil {
		return "", err
	}
	return ipList.ID, nil
}

func mapToSliceCreateRequest(mp map[cloudflare.IPListItemCreateRequest]bool) []cloudflare.IPListItemCreateRequest {
	slice := make([]cloudflare.IPListItemCreateRequest, len(mp))
	i := 0
	for k := range mp {
		slice[i] = k
		i++
	}

	return slice
}

func mapToSliceDeleteRequest(mp map[cloudflare.IPListItemDeleteItemRequest]bool) []cloudflare.IPListItemDeleteItemRequest {
	slice := make([]cloudflare.IPListItemDeleteItemRequest, len(mp))
	i := 0
	for k := range mp {
		slice[i] = k
		i++
	}
	return slice
}
