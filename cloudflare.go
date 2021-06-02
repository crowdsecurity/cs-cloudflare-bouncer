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

var CloudflareActionByDecisionType = map[string]string{
	"captcha":      "challenge",
	"ban":          "block",
	"js_challenge": "js_challenge",
}

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
	Logger                  *log.Entry
	Account                 CloudflareAccount
	ZoneLocks               []ZoneLock
	Ctx                     context.Context
	LAPIStream              chan *models.DecisionsStreamResponse
	IPListByRemedy          map[string]cloudflare.IPList
	UpdateFrequency         time.Duration
	CloudflareIDByIP        map[string]map[string]string // "ip_list_id" -> "ip" ->"cf_id"
	NewIPSet                map[string]map[string]struct{}
	ExpiredIPSet            map[string]map[string]struct{}
	NewASDecisions          []*models.Decision
	ExpiredASDecisions      []*models.Decision
	NewCountryDecisions     []*models.Decision
	ExpiredCountryDecisions []*models.Decision
	API                     cloudflareAPI
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
			defer zoneLock.Unlock()
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
			defer zoneLock.Unlock()
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
	IPLists, err := worker.API.ListIPLists(worker.Ctx)
	if err != nil {
		return err
	}

	for _, IPList := range worker.IPListByRemedy {
		id := worker.getIPListID(IPList.Name, IPLists) // requires ip list name
		if id == nil {
			worker.Logger.Infof("ip list %s does not exists", IPList.Name)
			return nil
		}

		worker.Logger.Infof("ip list %s already exists", IPList.Name)
		err = worker.removeIPListDependencies(IPList.Name) // requires ip list name
		if err != nil {
			return err
		}

		_, err = worker.API.DeleteIPList(worker.Ctx, *id)
		if err != nil {
			return err
		}
	}
	return nil
}

func (worker *CloudflareWorker) removeIPListDependencies(IPListName string) error {
	zones, err := worker.API.ListZones(worker.Ctx)
	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}
	worker.Logger.Debugf("found %d zones on this account", len(zones))
	if err != nil {
		return err
	}

	err = worker.deleteRulesContainingString(fmt.Sprintf("$%s", IPListName), extractZoneIDs(worker.Account.Zones))
	if err != nil {
		return err
	}
	// A Filter can exist on it's own, they are not visible on UI, they are API only.
	// Clear these Filters.
	err = worker.deleteFiltersContainingString(fmt.Sprintf("$%s", IPListName), extractZoneIDs(worker.Account.Zones))
	if err != nil {
		return err
	}
	return nil
}

func (worker *CloudflareWorker) getIPListID(IPListName string, IPLists []cloudflare.IPList) *string {
	for _, ipList := range IPLists {
		if ipList.Name == IPListName {
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

	for remedy, IPList := range worker.IPListByRemedy {
		worker.IPListByRemedy[remedy], err = worker.API.CreateIPList(worker.Ctx, IPList.Name, fmt.Sprintf("%s IP list by crowdsec", remedy), "ip")
		if err != nil {
			return err
		}
	}
	return nil
}

func (worker *CloudflareWorker) SetUpRules() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for _, remedy := range zone.Remediation {
			ruleExpression := fmt.Sprintf("ip.src in $%s", worker.IPListByRemedy[remedy].Name)
			firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: ruleExpression}, Action: remedy, Description: fmt.Sprintf("%s if in CrowdSec IP list", zone.Remediation)}}
			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, firewallRules)
			if err != nil {
				worker.Logger.WithFields(log.Fields{"zone_id": zone.ID}).Errorf("error %s in creating firewall rule %s", err.Error(), ruleExpression)
				return err
			}
		}
		zoneLogger.Info("firewall rules created")
	}
	worker.Logger.Info("setup of firewall rules complete")
	return nil
}

func (worker *CloudflareWorker) AddNewIPs() error {
	for remedy, IPList := range worker.IPListByRemedy {
		addIPs := make([]cloudflare.IPListItemCreateRequest, 0)
		for ip := range worker.NewIPSet[remedy] {
			addIPs = append(addIPs, cloudflare.IPListItemCreateRequest{
				IP:      ip,
				Comment: "Sent by CrowdSec",
			})
		}
		if len(addIPs) > 0 {
			items, err := worker.API.CreateIPListItems(worker.Ctx, IPList.ID, addIPs)
			if err != nil {
				return err
			}
			for _, item := range items {
				if worker.CloudflareIDByIP[IPList.ID] == nil {
					worker.CloudflareIDByIP[IPList.ID] = make(map[string]string)
				}
				worker.CloudflareIDByIP[IPList.ID][item.IP] = item.ID
			}
			worker.Logger.Infof("added %d ips in %s ip list", len(addIPs), IPList.ID)
		}
		worker.NewIPSet[remedy] = make(map[string]struct{})
	}
	return nil
}

func (worker *CloudflareWorker) DeleteIPs() error {
	for remedy, IPList := range worker.IPListByRemedy {
		req := cloudflare.IPListItemDeleteRequest{Items: make([]cloudflare.IPListItemDeleteItemRequest, 0)}
		for ip := range worker.ExpiredIPSet[remedy] {
			if id, ok := worker.CloudflareIDByIP[IPList.ID][ip]; ok {
				req.Items = append(req.Items, cloudflare.IPListItemDeleteItemRequest{ID: id})
			}
		}
		if len(req.Items) > 0 {
			deletedItems, err := worker.API.DeleteIPListItems(worker.Ctx, IPList.ID, req)
			if err != nil {
				return err
			}
			worker.Logger.Infof("deleted %d ips from %s ip list", len(req.Items), IPList.ID)
			for _, item := range deletedItems {
				delete(worker.CloudflareIDByIP[IPList.ID], item.IP)
			}
		}
		worker.ExpiredIPSet[remedy] = make(map[string]struct{})
	}
	return nil
}

func (worker *CloudflareWorker) Init() error {
	var err error

	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	worker.CloudflareIDByIP = make(map[string]map[string]string)
	worker.IPListByRemedy = make(map[string]cloudflare.IPList)
	worker.NewIPSet = make(map[string]map[string]struct{})
	worker.ExpiredIPSet = make(map[string]map[string]struct{})

	if worker.API == nil {
		worker.API, err = cloudflare.NewWithAPIToken(worker.Account.Token, cloudflare.UsingAccount(worker.Account.ID))
	}
	zones, err := worker.API.ListZones(worker.Ctx)
	if err != nil {
		return err
	}
	zoneByID := make(map[string]cloudflare.Zone)

	for _, zone := range zones {
		zoneByID[zone.ID] = zone
	}
	for _, z := range worker.Account.Zones {
		if zone, ok := zoneByID[z.ID]; ok {
			if !zone.Plan.IsSubscribed && len(z.Remediation) > 1 {
				return fmt.Errorf("zone %s 's plan doesn't support multiple remediations", z.ID)
			}

			for _, remedy := range z.Remediation {
				listName := fmt.Sprintf("%s_%s", worker.Account.IPListPrefix, remedy)
				worker.IPListByRemedy[remedy] = cloudflare.IPList{Name: listName}
				worker.NewIPSet[remedy] = make(map[string]struct{})
				worker.ExpiredIPSet[remedy] = make(map[string]struct{})
			}
		} else {
			return fmt.Errorf("account %s doesn't have access to one %s", worker.Account.ID, z.ID)
		}
	}

	worker.CloudflareIDByIP = make(map[string]map[string]string)
	return err
}

func (worker *CloudflareWorker) CleanUp() {
	worker.Logger.Error("stopping")
}

func (worker *CloudflareWorker) CollectLAPIStream(streamDecision *models.DecisionsStreamResponse) {
	worker.Logger.Infof("received %d new decisions", len(streamDecision.New)+len(streamDecision.Deleted))
	for _, decision := range streamDecision.New {
		switch scope := strings.ToUpper(*decision.Scope); scope {
		case "IP", "RANGE":
			cfAction := CloudflareActionByDecisionType[*decision.Type]
			if IPSet, ok := worker.NewIPSet[cfAction]; ok {
				IPSet[*decision.Value] = struct{}{}
			}
		case "COUNTRY":
			worker.NewCountryDecisions = append(worker.NewCountryDecisions, decision)

		case "AS":
			worker.NewASDecisions = append(worker.NewASDecisions, decision)

		}
	}
	for _, decision := range streamDecision.Deleted {
		switch scope := strings.ToUpper(*decision.Scope); scope {
		case "IP", "RANGE":
			cfAction := CloudflareActionByDecisionType[*decision.Type]
			if IPSet, ok := worker.ExpiredIPSet[cfAction]; ok {
				IPSet[*decision.Value] = struct{}{}
			}

		case "COUNTRY":
			worker.ExpiredCountryDecisions = append(worker.ExpiredCountryDecisions, decision)

		case "AS":
			worker.ExpiredASDecisions = append(worker.ExpiredASDecisions, decision)
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

		ruleSet := make(map[string]struct{})
		for _, rule := range rules {
			ruleSet[rule.Expression] = struct{}{}
		}

		ASBans := make([]cloudflare.FirewallRule, 0)
		for _, ASBan := range worker.NewASDecisions {
			expr := fmt.Sprintf("ip.geoip.asnum eq %s", *ASBan.Value)
			var action string
			defaulted := false
			if _, ok := CloudflareActionByDecisionType[*ASBan.Type]; !ok {
				action = zone.Remediation[0]
				defaulted = true
			} else {
				action = CloudflareActionByDecisionType[*ASBan.Type]
			}
			rule := cloudflare.FirewallRule{
				Filter:      cloudflare.Filter{Expression: expr},
				Description: "CrowdSec AS Ban",
				Action:      action,
			}
			if _, existsInRuleSet := ruleSet[expr]; !existsInRuleSet {
				ASBans = append(ASBans, rule)
				ruleSet[expr] = struct{}{}
			} else if !defaulted && existsInRuleSet {
				for i, r := range ASBans {
					if r.Filter.Expression == expr {
						ASBans = append(ASBans[:i], ASBans[i+1:]...)
					}
				}
				ASBans = append(ASBans, rule)
			} else {
				zoneLogger.Debugf("rule with expression %s already exists", expr)
			}
		}
		if len(ASBans) > 0 {
			for _, ban := range ASBans {
				err := worker.deleteRulesContainingString(ban.Filter.Expression, []string{zone.ID})
				if err != nil {
					return err
				}
				err = worker.deleteFiltersContainingString(ban.Filter.Expression, []string{zone.ID})
				if err != nil {
					return err
				}
			}

			zoneLogger.Infof("sending %d AS bans", len(ASBans))
			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, ASBans)
			if err != nil {
				worker.Logger.Error(err)
				return err
			}
		}
	}
	worker.NewASDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteASBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for _, ASBan := range worker.ExpiredASDecisions {
			expr := fmt.Sprintf("ip.geoip.asnum eq %s", *ASBan.Value)
			err := worker.deleteRulesContainingString(expr, extractZoneIDs(worker.Account.Zones))
			if err != nil {
				return err
			}
			err = worker.deleteFiltersContainingString(expr, extractZoneIDs(worker.Account.Zones))
			if err != nil {
				return err
			}
		}
		if len(worker.ExpiredASDecisions) > 0 {
			zoneLogger.Infof("deleted %d AS bans", len(worker.ExpiredASDecisions))
		}

	}
	worker.ExpiredASDecisions = make([]*models.Decision, 0)
	return nil

}

func (worker *CloudflareWorker) SendCountryBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		countryBans := make([]cloudflare.FirewallRule, 0)

		//This set is used to ensure we don't send dups
		countryBanSet := make(map[string]struct{})
		for _, countryBan := range worker.NewCountryDecisions {
			expr := fmt.Sprintf(`ip.geoip.country eq "%s"`, *countryBan.Value)
			var action string
			defaulted := false
			if a, ok := CloudflareActionByDecisionType[*countryBan.Type]; ok {
				action = a
			} else {
				action = zone.Remediation[0]
				defaulted = true
			}

			rule := cloudflare.FirewallRule{
				Description: "Country Ban by CrowdSec",
				Filter: cloudflare.Filter{
					Expression: expr,
				},
				Action: action,
			}

			if _, existsInRuleSet := countryBanSet[expr]; !existsInRuleSet {
				countryBans = append(countryBans, rule)
				countryBanSet[expr] = struct{}{}
			} else if !defaulted && existsInRuleSet {
				for i, r := range countryBans {
					if r.Filter.Expression == expr {
						countryBans = append(countryBans[:i], countryBans[i+1:]...)
					}
				}
				countryBans = append(countryBans, rule)
			} else {
				zoneLogger.Debugf("rule with expression %s already exists", expr)
			}

		}
		if len(countryBans) > 0 {
			for _, ban := range countryBans {
				err := worker.deleteRulesContainingString(ban.Filter.Expression, []string{zone.ID})
				if err != nil {
					return err
				}
				err = worker.deleteFiltersContainingString(ban.Filter.Expression, []string{zone.ID})
				if err != nil {
					return err
				}
			}
			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, countryBans)
			if err != nil {
				return err
			}
			zoneLogger.Infof("added %d country bans", len(countryBans))
		}
	}
	worker.NewCountryDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteCountryBans() error {
	for _, countryBan := range worker.ExpiredCountryDecisions {
		expr := fmt.Sprintf(`ip.geoip.country eq "%s"`, *countryBan.Value)
		err := worker.deleteRulesContainingString(expr, extractZoneIDs(worker.Account.Zones))
		if err != nil {
			return err
		}
		err = worker.deleteFiltersContainingString(expr, extractZoneIDs(worker.Account.Zones))
		if err != nil {
			return err
		}
	}
	worker.ExpiredCountryDecisions = make([]*models.Decision, 0)
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
			// TODO: all of the below functions can be grouped and ran in separate goroutines for better performance
			err := worker.DeleteIPs()
			if err != nil {
				return err
			}

			err = worker.AddNewIPs()
			if err != nil {
				return err
			}

			if len(worker.ExpiredCountryDecisions) > 1 {
				err = worker.DeleteCountryBans()
				if err != nil {
					return err
				}
			}

			if len(worker.NewCountryDecisions) > 0 {
				err = worker.SendCountryBans()
				if err != nil {
					return err
				}
			}

			if len(worker.ExpiredASDecisions) > 0 {
				err = worker.DeleteASBans()
				if err != nil {
					return err
				}
			}

			if len(worker.NewASDecisions) > 0 {
				err = worker.SendASBans()
				if err != nil {
					return err
				}
			}

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("processing new and deleted decisions from crowdsec LAPI")
			worker.CollectLAPIStream(decisions)
		}
	}

}
