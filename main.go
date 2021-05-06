package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/cloudflare-go"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func deleteExistingCrowdSecIpList(ctx context.Context, api *cloudflare.API) {
	ipLists, _ := api.ListIPLists(ctx)
	id, err := getCrowdSecIPListId(ipLists)
	if err != nil {
		return
	}

	resp, err := api.DeleteIPList(ctx, id)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v", resp)

}

func getCrowdSecIPListId(ipLists []cloudflare.IPList) (string, error) {
	for _, ipList := range ipLists {
		if ipList.Name == "crowdsec" {
			return ipList.ID, nil
		}
	}
	return "", errors.New("crowdsec ip list not found")
}

func main() {

	ctx := context.Background()
	conf, err := NewConfig("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	cfApi, _ := cloudflare.NewWithAPIToken(conf.CloudflareAPIToken, cloudflare.UsingAccount(conf.CloudflareAccountID))
	deleteExistingCrowdSecIpList(ctx, cfApi)
	ipList, err := cfApi.CreateIPList(ctx, "crowdsec", "IP list managed by crowdsec bouncer", "ip")
	if err != nil {
		log.Fatal(err)
	}

	csLapi := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: "20s",
	}

	cloudflareIdByIp := make(map[string]string)

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go csLapi.Run()

	for streamDecision := range csLapi.Stream {
		deleteIps := make([]cloudflare.IPListItemDeleteItemRequest, 0)
		addIps := make([]cloudflare.IPListItemCreateRequest, 0)
		addIpsMap := make(map[cloudflare.IPListItemCreateRequest]bool)

		for _, decision := range streamDecision.Deleted {
			if cloudflareIdByIp[*decision.Value] != "" {
				deleteIps = append(deleteIps, cloudflare.IPListItemDeleteItemRequest{ID: cloudflareIdByIp[*decision.Value]})
				delete(cloudflareIdByIp, *decision.Value)
			}
		}

		for _, decision := range streamDecision.New {
			addIpsMap[cloudflare.IPListItemCreateRequest{
				IP:      *decision.Value,
				Comment: "Added by crowdsec bouncer",
			}] = true
		}

		for k, _ := range addIpsMap {
			addIps = append(addIps, k)
		}

		if len(addIps) > 0 {
			ipItems, err := cfApi.CreateIPListItems(ctx, ipList.ID, addIps)
			if err != nil {
				log.Fatal(err)
			}

			for _, ipItem := range ipItems {
				cloudflareIdByIp[ipItem.IP] = ipItem.ID
			}
		}

		//TODO
		// if len(deleteIps) > 0 {

		// }

	}

}
