package main

import (
	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func CollectLAPIStream(streamDecision *models.DecisionsStreamResponse, deleteIPMap map[cloudflare.IPListItemDeleteItemRequest]bool, addIPMap map[cloudflare.IPListItemCreateRequest]bool, cloudflareIDByIP map[string]string) {
	for _, decision := range streamDecision.New {
		addIPMap[cloudflare.IPListItemCreateRequest{
			IP:      *decision.Value,
			Comment: "Added by crowdsec bouncer",
		}] = true
	}
	for _, decision := range streamDecision.Deleted {
		if _, ok := cloudflareIDByIP[*decision.Value]; ok {
			deleteIPMap[cloudflare.IPListItemDeleteItemRequest{ID: cloudflareIDByIP[*decision.Value]}] = true
			delete(cloudflareIDByIP, *decision.Value)
		}
	}

}
