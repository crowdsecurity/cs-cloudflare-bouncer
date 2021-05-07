package main

import (
	"context"
	"errors"
	"log"

	"github.com/cloudflare/cloudflare-go"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func clearExistingCrowdSecIpList(ctx context.Context, cfApi *cloudflare.API, conf *blockerConfig) error {
	ipLists, err := cfApi.ListIPLists(ctx)
	if err != nil {
		return err
	}

	id, err := getCrowdSecIPListId(ipLists)
	if err != nil {
		return err
	}

	removeIpListDependencies(ctx, cfApi, conf)

	_, err = cfApi.DeleteIPList(ctx, id)
	if err != nil {
		return err
	}
	return nil
}

func removeIpListDependencies(ctx context.Context, cfApi *cloudflare.API, conf *blockerConfig) error {
	rules, err := cfApi.FirewallRules(ctx, conf.CloudflareZoneID, cloudflare.PaginationOptions{})
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if rule.Filter.Expression == "ip.src in $crowdsec" {
			err := cfApi.DeleteFirewallRule(ctx, conf.CloudflareZoneID, rule.ID)
			if err != nil {
				return err
			}

			err = cfApi.DeleteFilter(ctx, conf.CloudflareZoneID, rule.Filter.ID)
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func getCrowdSecIPListId(ipLists []cloudflare.IPList) (string, error) {
	for _, ipList := range ipLists {
		if ipList.Name == "crowdsec" {
			return ipList.ID, nil
		}
	}
	return "", errors.New("crowdsec ip list not found")
}

func setUpIpListAndFirewall(ctx context.Context, cfApi *cloudflare.API, conf *blockerConfig) (string, error) {
	clearExistingCrowdSecIpList(ctx, cfApi, conf)
	ipList, err := cfApi.CreateIPList(ctx, "crowdsec", "IP list managed by crowdsec bouncer", "ip")
	if err != nil {
		return "", err
	}

	firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: "ip.src in $crowdsec"}, Action: conf.Action}}
	_, err = cfApi.CreateFirewallRules(ctx, conf.CloudflareZoneID, firewallRules)
	if err != nil {
		return "", err
	}
	return ipList.ID, nil
}

func main() {

	ctx := context.Background()
	conf, err := NewConfig("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	cfApi, err := cloudflare.NewWithAPIToken(
		conf.CloudflareAPIToken, cloudflare.UsingAccount(conf.CloudflareAccountID))

	if err != nil {
		log.Fatal(err)
	}

	ipListId, err := setUpIpListAndFirewall(ctx, cfApi, conf)
	if err != nil {
		log.Fatal(err)
	}

	csLapi := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: conf.UpdateFrequencyYAML,
	}

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go csLapi.Run()
	cloudflareIdByIp := make(map[string]string)
	for streamDecision := range csLapi.Stream {
		deleteIpsMap := make(map[cloudflare.IPListItemDeleteItemRequest]bool)
		addIpsMap := make(map[cloudflare.IPListItemCreateRequest]bool)

		for _, decision := range streamDecision.Deleted {
			if cloudflareIdByIp[*decision.Value] != "" {
				deleteIpsMap[cloudflare.IPListItemDeleteItemRequest{ID: cloudflareIdByIp[*decision.Value]}] = true
				delete(cloudflareIdByIp, *decision.Value)
			}
		}

		for _, decision := range streamDecision.New {
			addIpsMap[cloudflare.IPListItemCreateRequest{
				IP:      *decision.Value,
				Comment: "Added by crowdsec bouncer",
			}] = true
		}

		addIps := make([]cloudflare.IPListItemCreateRequest, 0)
		for k := range addIpsMap {
			addIps = append(addIps, k)
		}

		if len(addIps) > 0 {
			ipItems, err := cfApi.CreateIPListItems(ctx, ipListId, addIps)
			if err != nil {
				log.Fatal(err)
			}

			for _, ipItem := range ipItems {
				cloudflareIdByIp[ipItem.IP] = ipItem.ID
			}
		}

		deleteIps := make([]cloudflare.IPListItemDeleteItemRequest, 0)
		for k := range deleteIpsMap {
			deleteIps = append(deleteIps, k)
		}

		if len(deleteIps) > 0 {
			_, err := cfApi.DeleteIPListItems(ctx, ipListId, cloudflare.IPListItemDeleteRequest{Items: deleteIps})
			if err != nil {
				log.Fatal(err)
			}
		}

	}

}
