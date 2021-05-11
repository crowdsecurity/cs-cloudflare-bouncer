package main

import (
	"fmt"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestCrowdsec(t *testing.T) {

	ip1 := "1.2.3.4"
	ip2 := "1.2.3.5"
	addedDecisions := &models.Decision{Value: &ip1}
	deletedDecisions :=  &models.Decision{Value: &ip2}
	dummyResponse := &models.DecisionsStreamResponse{
		New: []*models.Decision{addedDecisions},
		Deleted: []*models.Decision{deletedDecisions},
	}

	deleteIPMap := make(map[cloudflare.IPListItemDeleteItemRequest]bool)
	addIPMap := make(map[cloudflare.IPListItemCreateRequest]bool)
	cloudflareIDByIP := make(map[string]string)
	cloudflareIDByIP["1.2.3.5"] = "abcd"

	CollectLAPIStream(dummyResponse, deleteIPMap, addIPMap, cloudflareIDByIP)

	if len(cloudflareIDByIP) != 1 {
		fmt.Errorf("expected 1 key in 'cloudflareIDByIP' but found %d", len(cloudflareIDByIP))
	}

	if len(deleteIPMap) != 1 {
		fmt.Errorf("expected 1 key in 'deleteIPMap' but found %d", len(deleteIPMap))
	}

	if len(addIPMap) != 1 {
		fmt.Errorf("expected 1 key in 'deleteIPMap' but found %d", len(addIPMap))
	}
}
