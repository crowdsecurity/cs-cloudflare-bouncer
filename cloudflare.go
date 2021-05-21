package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	log "github.com/sirupsen/logrus"
)

type ZoneLock struct {
	Lock   *sync.Mutex
	ZoneID string
}

type cloudflareAPI interface {
	Filters(ctx context.Context, zoneID string, pageOpts cloudflare.PaginationOptions) ([]cloudflare.Filter, error)
	ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error)
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

type CloudflareWorker struct {
	Logger           *log.Entry
	Account          CloudflareAccount
	ZoneLocks        []ZoneLock
	Ctx              context.Context
	LAPIStream       chan *models.DecisionsStreamResponse
	IPListName       string
	IPListID         string
	UpdateFrequency  time.Duration
	CloudflareIDByIP map[string]string
	DeleteIPMap      map[cloudflare.IPListItemDeleteItemRequest]bool
	AddIPMap         map[cloudflare.IPListItemCreateRequest]bool
	API              cloudflareAPI
}

func (worker *CloudflareWorker) getMutexByZoneID(zoneID string) (*sync.Mutex, error) {
	for _, zoneLock := range worker.ZoneLocks {
		if zoneLock.ZoneID == zoneID {
			return zoneLock.Lock, nil
		}
	}
	return nil, fmt.Errorf("zone lock for the zone id %s not found", zoneID)

}
func (worker *CloudflareWorker) deleteExistingIPList() error {
	ipLists, err := worker.API.ListIPLists(worker.Ctx)
	if err != nil {
		return err
	}

	id := worker.getIPListID(ipLists)
	if id == nil {
		worker.Logger.Infof("ip list %s does not exists", worker.IPListName)
		return nil
	}
	worker.Logger.Infof("ip list %s already exists", worker.IPListName)
	err = worker.removeIPListDependencies()
	if err != nil {
		return err
	}

	_, err = worker.API.DeleteIPList(worker.Ctx, *id)
	if err != nil {
		return err
	}
	return nil
}

func (worker *CloudflareWorker) removeIPListDependencies() error {
	zones, err := worker.API.ListZones(worker.Ctx)
	worker.Logger.Debugf("found %d zones on this account", len(zones))
	if err != nil {
		return err
	}

	// This clears all zone-specific firewall rules.
	for _, zone := range zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		zoneLock, err := worker.getMutexByZoneID(zone.ID)
		if err == nil {
			zoneLock.Lock()
			zoneLogger.Debug("zone locked")
			defer func() {
				zoneLogger.Info("zone unlocked")
				zoneLock.Unlock()
			}()
		} else {
			// this happens if the zone is directly not specified in config
			// but we still need to look for references of ip list among such zones
			zoneLogger.Debug("zone locker not found")
		}

		rules, err := worker.API.FirewallRules(worker.Ctx, zone.ID, cloudflare.PaginationOptions{})
		zoneLogger.Debugf("found %d firewall rules", len(rules))
		if err != nil {
			return err
		}

		// Each firewall rule owns one "Filter", clear it if it references our IP list
		for _, rule := range rules {
			if strings.Contains(rule.Filter.Expression, "$"+worker.IPListName) {
				err := worker.API.DeleteFirewallRule(worker.Ctx, zone.ID, rule.ID)
				if err != nil {
					return err
				}
				zoneLogger.Debugf("deleted %s firewall rule", rule.ID)
			}
		}

		// A Filter can exist on it's own (without a firewall rule), super weird.
		// Clear these "orphaned" Filters.
		filters, err := worker.API.Filters(worker.Ctx, zone.ID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}

		worker.Logger.Infof("found %d filters", len(filters))
		for _, filter := range filters {
			if strings.Contains(filter.Expression, "$"+worker.IPListName) {
				err := worker.API.DeleteFilter(worker.Ctx, zone.ID, filter.ID)
				if err != nil {
					return err
				}
				worker.Logger.Debugf("deleted %s firewall filter with expression %s", filter.ID, filter.Expression)
			}
		}
	}
	return nil
}

func (worker *CloudflareWorker) getIPListID(ipLists []cloudflare.IPList) *string {
	for _, ipList := range ipLists {
		if ipList.Name == worker.IPListName {
			return &ipList.ID
		}
	}
	return nil
}

func (worker *CloudflareWorker) setUpIPList() error {
	err := worker.deleteExistingIPList()
	if err != nil {
		return err
	}

	ipList, err := worker.API.CreateIPList(worker.Ctx, worker.IPListName, "IP list managed by crowdsec bouncer", "ip")
	if err != nil {
		return err
	}
	worker.IPListID = ipList.ID
	return nil
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

func (worker *CloudflareWorker) SetUpRules() error {
	for _, zone := range worker.Account.Zones {
		ruleExpression := "ip.src in $" + worker.IPListName
		firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: ruleExpression}, Action: zone.Remediation}}
		_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, firewallRules)
		if err != nil {
			worker.Logger.WithFields(log.Fields{"zone_id": zone.ID}).Errorf("error %s in creating firewall rule %s", err.Error(), ruleExpression)
			return err
		}
		worker.Logger.WithFields(log.Fields{"zone_id": zone.ID}).Info("firewall rule created")
	}
	worker.Logger.Info("setup of firewall rules complete")
	return nil
}

func (worker *CloudflareWorker) AddIPs() error {
	addIPList := mapToSliceCreateRequest(worker.AddIPMap)
	if len(addIPList) > 0 {
		ipItems, err := worker.API.CreateIPListItems(worker.Ctx, worker.IPListID, addIPList)
		worker.Logger.Infof("making API call to cloudflare for adding '%d' decisions", len(addIPList))
		if err != nil {
			worker.Logger.Error(err.Error())
			return err
		}

		for _, ipItem := range ipItems {
			worker.CloudflareIDByIP[ipItem.IP] = ipItem.ID
		}
	}
	worker.AddIPMap = make(map[cloudflare.IPListItemCreateRequest]bool)
	return nil
}

func (worker *CloudflareWorker) DeleteIPs() error {
	deleteIPList := mapToSliceDeleteRequest(worker.DeleteIPMap)
	if len(deleteIPList) > 0 {
		_, err := worker.API.DeleteIPListItems(worker.Ctx, worker.IPListID, cloudflare.IPListItemDeleteRequest{Items: deleteIPList})
		worker.Logger.Infof("making API call to cloudflare to delete '%d' decisions", len(deleteIPList))
		if err != nil {
			worker.Logger.Error(err.Error())
			return err
		}
	}
	worker.DeleteIPMap = make(map[cloudflare.IPListItemDeleteItemRequest]bool)
	return nil
}

func (worker *CloudflareWorker) Init() error {
	var err error

	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	worker.DeleteIPMap = make(map[cloudflare.IPListItemDeleteItemRequest]bool)
	worker.AddIPMap = make(map[cloudflare.IPListItemCreateRequest]bool)
	worker.CloudflareIDByIP = make(map[string]string)

	if worker.API == nil {
		worker.API, err = cloudflare.NewWithAPIToken(worker.Account.Token, cloudflare.UsingAccount(worker.Account.ID))
	}

	return err
}

func (worker *CloudflareWorker) CleanUp() {
	worker.Logger.Error("stopping")
}

func (worker *CloudflareWorker) CollectLAPIStream(streamDecision *models.DecisionsStreamResponse) {
	for _, decision := range streamDecision.New {
		worker.AddIPMap[cloudflare.IPListItemCreateRequest{
			IP:      *decision.Value,
			Comment: "Added by crowdsec bouncer",
		}] = true
	}
	for _, decision := range streamDecision.Deleted {
		if _, ok := worker.CloudflareIDByIP[*decision.Value]; ok {
			worker.DeleteIPMap[cloudflare.IPListItemDeleteItemRequest{ID: worker.CloudflareIDByIP[*decision.Value]}] = true
			delete(worker.CloudflareIDByIP, *decision.Value)
		}
	}

}

func (worker *CloudflareWorker) Run() error {
	defer worker.CleanUp()
	err := worker.Init()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}

	worker.Logger.Debug("setup of API complete")
	err = worker.setUpIPList()

	if err != nil {
		worker.Logger.Errorf("error %s in creating IP List", err.Error())
		return err
	}

	worker.Logger.Debug("ip list setup complete")
	err = worker.SetUpRules()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}

	ticker := time.NewTicker(worker.UpdateFrequency)
	for {
		select {
		case <-ticker.C:
			worker.AddIPs()
			worker.DeleteIPs()
			// worker.AddCountryBan()
			// worker.RemoveCountryBan()

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("processing new and deleted decisions from crowdsec LAPI")
			worker.CollectLAPIStream(decisions)
		}
	}

}
