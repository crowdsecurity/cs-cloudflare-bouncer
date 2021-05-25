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
	DeleteFirewallRules(ctx context.Context, zoneID string, firewallRuleIDs []string) error
	DeleteFilter(ctx context.Context, zone string, id string) error
	FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error)
	CreateIPListItems(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) ([]cloudflare.IPListItem, error)
	DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error)
	DeleteFilters(ctx context.Context, zoneID string, filterIDs []string) error
}

type CloudflareWorker struct {
	Logger            *log.Entry
	Account           CloudflareAccount
	ZoneLocks         []ZoneLock
	Ctx               context.Context
	LAPIStream        chan *models.DecisionsStreamResponse
	IPListName        string
	IPListID          string
	UpdateFrequency   time.Duration
	CloudflareIDByIP  map[string]string
	DeleteIPMap       map[cloudflare.IPListItemDeleteItemRequest]bool
	AddIPMap          map[cloudflare.IPListItemCreateRequest]bool
	AddASBans         []string
	RemoveASBans      []string
	AddCountryBans    []cloudflare.FirewallRule
	RemoveCountryBans []string // cloudflare country ban ids
	API               cloudflareAPI
}

func (worker *CloudflareWorker) getMutexByZoneID(zoneID string) (*sync.Mutex, error) {
	for _, zoneLock := range worker.ZoneLocks {
		if zoneLock.ZoneID == zoneID {
			return zoneLock.Lock, nil
		}
	}
	return nil, fmt.Errorf("zone lock for the zone id %s not found", zoneID)
}

func extractZoneIDs(zones []CloudflareZone) []string {
	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}
	return zoneIDs
}

func (worker *CloudflareWorker) deleteRulesContainingString(str string, zonesIDs []string) error {
	for _, zoneID := range zonesIDs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneID})
		zoneLock, err := worker.getMutexByZoneID(zoneID)
		if err == nil {
			zoneLock.Lock()
			zoneLogger.Debug("zone locked")
			defer func() {
				zoneLogger.Info("zone unlocked")
				zoneLock.Unlock()
			}()
		}
		rules, err := worker.API.FirewallRules(worker.Ctx, zoneID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}
		deleteRules := make([]string, 0)

		for _, rule := range rules {
			if strings.Contains(rule.Filter.Expression, str) {
				deleteRules = append(deleteRules, rule.ID)
			}
		}
		if len(deleteRules) > 0 {
			err = worker.API.DeleteFirewallRules(worker.Ctx, zoneID, deleteRules)
			if err != nil {
				return err
			}
			zoneLogger.Infof("deleted %d firewall rules containing the string %s", len(deleteRules), str)
		}

	}
	return nil
}

func (worker *CloudflareWorker) deleteFiltersContainingString(str string, zonesIDs []string) error {
	for _, zoneID := range zonesIDs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneID})
		zoneLock, err := worker.getMutexByZoneID(zoneID)
		if err == nil {
			zoneLock.Lock()
			zoneLogger.Debug("zone locked")
			defer func() {
				zoneLogger.Info("zone unlocked")
				zoneLock.Unlock()
			}()
		}
		filters, err := worker.API.Filters(worker.Ctx, zoneID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}
		deleteFilters := make([]string, 0)
		for _, filter := range filters {
			if strings.Contains(filter.Expression, str) {
				deleteFilters = append(deleteFilters, filter.ID)
				zoneLogger.Debugf("deleting %s filter with expression %s", filter.ID, filter.Expression)
			}
		}

		if len(deleteFilters) > 0 {
			zoneLogger.Infof("deleting %d filters", len(deleteFilters))
			err = worker.API.DeleteFilters(worker.Ctx, zoneID, deleteFilters)
			if err != nil {
				return err
			}
		}

	}
	return nil
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
	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}
	worker.Logger.Debugf("found %d zones on this account", len(zones))
	if err != nil {
		return err
	}

	err = worker.deleteRulesContainingString(fmt.Sprintf("$%s", worker.IPListName), extractZoneIDs(worker.Account.Zones))
	if err != nil {
		return err
	}
	// A Filter can exist on it's own, they are not visible on UI, they are API only.
	// Clear these Filters.
	err = worker.deleteFiltersContainingString(fmt.Sprintf("$%s", worker.IPListName), extractZoneIDs(worker.Account.Zones))
	if err != nil {
		return err
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
		ruleExpression := fmt.Sprintf("ip.src in $%s", worker.IPListName)
		firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: ruleExpression}, Action: zone.Remediation, Description: fmt.Sprintf("%s if in CrowdSec IP list", zone.Remediation)}}
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
	worker.Logger.Infof("received %d new decisions", len(streamDecision.New))
	for _, decision := range streamDecision.New {
		if strings.ToUpper(*decision.Scope) == "IP" {
			worker.AddIPMap[cloudflare.IPListItemCreateRequest{
				IP:      *decision.Value,
				Comment: "Added by crowdsec bouncer",
			}] = true
		} else if strings.ToUpper(*decision.Scope) == "COUNTRY" {
			filterExpression := fmt.Sprintf("ip.geoip.country eq %s", fmt.Sprintf(`"%s"`, *decision.Value))
			worker.AddCountryBans = append(worker.AddCountryBans, cloudflare.FirewallRule{
				Filter: cloudflare.Filter{Expression: filterExpression},
			})
		} else if strings.ToUpper(*decision.Scope) == "AS" {
			worker.AddASBans = append(worker.AddASBans, *decision.Value)
		}
	}
	for _, decision := range streamDecision.Deleted {

		if strings.ToUpper(*decision.Scope) == "COUNTRY" {
			expr := fmt.Sprintf("ip.geoip.country eq %s", fmt.Sprintf(`"%s"`, *decision.Value))
			decision.Value = &expr
		} else if strings.ToUpper(*decision.Scope) == "AS" {
			expr := fmt.Sprintf("ip.geoip.asnum eq %s", *decision.Value)
			decision.Value = &expr
		}

		if strings.ToUpper(*decision.Scope) == "IP" {
			if _, ok := worker.CloudflareIDByIP[*decision.Value]; ok {
				worker.DeleteIPMap[cloudflare.IPListItemDeleteItemRequest{ID: worker.CloudflareIDByIP[*decision.Value]}] = true
			}
		} else if strings.ToUpper(*decision.Scope) == "COUNTRY" {
			worker.Logger.Info("found country delete decision")
			worker.RemoveCountryBans = append(worker.RemoveCountryBans, worker.CloudflareIDByIP[*decision.Value])
		} else if strings.ToUpper(*decision.Scope) == "AS" {
			worker.Logger.Info("found AS delete decision")
			worker.RemoveASBans = append(worker.RemoveASBans, *decision.Value)
		}
	}

}

func (worker *CloudflareWorker) SendASBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		lock, _ := worker.getMutexByZoneID(zone.ID)
		lock.Lock()
		defer lock.Unlock()

		rules, err := worker.API.Filters(worker.Ctx, zone.ID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}

		ruleSet := make(map[string]bool)
		for _, rule := range rules {
			ruleSet[rule.Expression] = true
		}

		ASBans := make([]cloudflare.FirewallRule, 0)
		for _, ASBan := range worker.AddASBans {
			expression := fmt.Sprintf("ip.geoip.asnum eq %s", ASBan)
			if _, existsInRuleSet := ruleSet[expression]; !existsInRuleSet {
				ASBans = append(ASBans, cloudflare.FirewallRule{
					Filter:      cloudflare.Filter{Expression: expression},
					Description: "CrowdSec AS Ban",
					Action:      zone.Remediation,
				})
			} else {
				zoneLogger.Debugf("rule with expression %s already exists", expression)
			}
		}
		zoneLogger.Infof("sending %d AS bans", len(ASBans))
		if len(ASBans) > 0 {
			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, ASBans)
			if err != nil {
				worker.Logger.Error(err)
				return err
			}
		}
		worker.AddASBans = make([]string, 0)

	}
	return nil
}

func (worker *CloudflareWorker) DeleteASBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for _, ASBan := range worker.RemoveASBans {
			err := worker.deleteRulesContainingString(ASBan, extractZoneIDs(worker.Account.Zones))
			if err != nil {
				return err
			}
			err = worker.deleteFiltersContainingString(ASBan, extractZoneIDs(worker.Account.Zones))
			if err != nil {
				return err
			}
		}
		zoneLogger.Infof("deleted %d AS bans", len(worker.RemoveASBans))
		worker.RemoveASBans = make([]string, 0)
	}
	return nil

}

func (worker *CloudflareWorker) SendCountryBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		lock, _ := worker.getMutexByZoneID(zone.ID)
		lock.Lock()
		defer lock.Unlock()
		rules, err := worker.API.FirewallRules(worker.Ctx, zone.ID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}

		ruleSet := make(map[string]bool)
		for _, rule := range rules {
			ruleSet[rule.Filter.Expression] = true
		}
		countryBans := make([]cloudflare.FirewallRule, 0)
		for _, countryBan := range worker.AddCountryBans {
			_, existsInRuleSet := ruleSet[countryBan.Filter.Expression]
			_, alreadySent := worker.CloudflareIDByIP[countryBan.Filter.Expression]
			if !(existsInRuleSet || alreadySent) {
				countryBan.Action = zone.Remediation
				countryBans = append(countryBans, countryBan)
			} else {
				zoneLogger.Debugf("rule %s  already exists", countryBan.Filter.Expression)
			}
			ruleSet[countryBan.Filter.Expression] = true
		}
		if len(countryBans) > 0 {
			rules, err = worker.API.CreateFirewallRules(worker.Ctx, zone.ID, countryBans)
			if err != nil {
				zoneLogger.Debugf("error while creating rule +%v\n", rules)
				zoneLogger.Error(err)
				return err
			}
			for _, rule := range rules {
				worker.CloudflareIDByIP[rule.Filter.Expression] = rule.ID
			}
			zoneLogger.Infof("created %d rules to ban countries", len(worker.AddCountryBans))
		}
		worker.AddCountryBans = make([]cloudflare.FirewallRule, 0)

	}
	return nil
}

func (worker *CloudflareWorker) DeleteCountryBans() error {

	// cloudflare also provides API.DeleteFirewallRules to delete all the rules in one shot
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		if len(worker.RemoveCountryBans) > 0 {
			for _, ruleID := range worker.RemoveCountryBans {
				zoneLogger.Debugf("deleting rule %s", ruleID)
				err := worker.API.DeleteFirewallRule(worker.Ctx, zone.ID, ruleID)
				if err != nil {
					return err
				}
			}
			zoneLogger.Infof("deleted %d country ban rules", len(worker.RemoveCountryBans))
			worker.RemoveCountryBans = make([]string, 0)
		}
	}

	return nil
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
			err := worker.AddIPs()
			if err != nil {
				return err
			}
			err = worker.DeleteIPs()
			if err != nil {
				return err
			}
			// err = worker.SendCountryBans()
			// if err != nil {
			// 	return err
			// }
			// err = worker.DeleteCountryBans()
			// if err != nil {
			// 	return err
			// }
			err = worker.SendASBans()
			if err != nil {
				return err
			}
			err = worker.DeleteASBans()
			if err != nil {
				return err
			}

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("processing new and deleted decisions from crowdsec LAPI")
			worker.CollectLAPIStream(decisions)
		}
	}

}
