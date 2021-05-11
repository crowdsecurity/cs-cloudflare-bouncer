package main

import (
	"context"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/prometheus/common/log"
)

func deleteExistingCrowdSecIPList(ctx context.Context, cfAPI cloudflareAPI, conf *bouncerConfig) error {
	ipLists, err := cfAPI.ListIPLists(ctx)
	if err != nil {
		return err
	}

	id := getIPListID(ipLists)
	if id == nil {
		log.Info("ip list already exists")
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

func getIPListID(ipLists []cloudflare.IPList) *string {
	for _, ipList := range ipLists {
		if ipList.Name == "crowdsec" {
			return &ipList.ID
		}
	}
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
