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

type IPSet struct {
	BanSet         map[string]struct{}
	ChallengeSet   map[string]struct{}
	JSChallengeSet map[string]struct{}
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
	IPListByRemedy    map[string]cloudflare.IPList
	UpdateFrequency   time.Duration
	CloudflareIDByIP  map[string]map[string]string // "ip_list_id" -> "ip" ->"cf_id"
	AddIPs            IPSet
	RemoveIPs         IPSet
	AddASBans         []string
	RemoveASBans      []string
	AddCountryBans    []string
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

	createIPListItemsFromSet := func(set map[string]struct{}, IPListID string) error {
		addIPs := make([]cloudflare.IPListItemCreateRequest, 0)
		for ip, _ := range set {
			addIPs = append(addIPs, cloudflare.IPListItemCreateRequest{
				IP:      ip,
				Comment: "Sent by CrowdSec",
			})
		}
		if len(addIPs) > 0 {
			items, err := worker.API.CreateIPListItems(worker.Ctx, IPListID, addIPs)
			if err != nil {
				return err
			}
			for _, item := range items {
				if worker.CloudflareIDByIP[IPListID] == nil {
					worker.CloudflareIDByIP[IPListID] = make(map[string]string)
				}
				worker.CloudflareIDByIP[IPListID][item.IP] = item.ID
			}
			worker.Logger.Infof("add %d ips in %s ip list", len(items), IPListID)
		}
		return nil
	}

	err := createIPListItemsFromSet(worker.AddIPs.BanSet, worker.IPListByRemedy["block"].ID)
	if err != nil {
		return err
	}
	err = createIPListItemsFromSet(worker.AddIPs.JSChallengeSet, worker.IPListByRemedy["js_challenge"].ID)
	if err != nil {
		return err
	}
	err = createIPListItemsFromSet(worker.AddIPs.ChallengeSet, worker.IPListByRemedy["challenge"].ID)
	if err != nil {
		return err
	}
	worker.AddIPs.BanSet = make(map[string]struct{})
	worker.AddIPs.JSChallengeSet = make(map[string]struct{})
	worker.AddIPs.ChallengeSet = make(map[string]struct{})
	return nil
}

func (worker *CloudflareWorker) DeleteIPs() error {

	deleteIPListItemsFromSet := func(set map[string]struct{}, IPListID string) error {
		req := cloudflare.IPListItemDeleteRequest{Items: make([]cloudflare.IPListItemDeleteItemRequest, 0)}
		for ip, _ := range set {
			if id, ok := worker.CloudflareIDByIP[IPListID][ip]; ok {
				req.Items = append(req.Items, cloudflare.IPListItemDeleteItemRequest{ID: id})
			}
		}
		if len(req.Items) > 0 {
			deletedItems, err := worker.API.DeleteIPListItems(worker.Ctx, IPListID, req)
			if err != nil {
				return err
			}
			worker.Logger.Infof("deleted %d ips from %s ip list", len(deletedItems), IPListID)
			for _, item := range deletedItems {
				delete(worker.CloudflareIDByIP[IPListID], item.IP)
			}
		}
		return nil
	}
	err := deleteIPListItemsFromSet(worker.RemoveIPs.BanSet, worker.IPListByRemedy["block"].ID)
	if err != nil {
		return err
	}
	err = deleteIPListItemsFromSet(worker.RemoveIPs.JSChallengeSet, worker.IPListByRemedy["js_challenge"].ID)
	if err != nil {
		return err
	}
	err = deleteIPListItemsFromSet(worker.RemoveIPs.ChallengeSet, worker.IPListByRemedy["challenge"].ID)
	if err != nil {
		return err
	}

	worker.RemoveIPs.BanSet = make(map[string]struct{})
	worker.RemoveIPs.JSChallengeSet = make(map[string]struct{})
	worker.RemoveIPs.ChallengeSet = make(map[string]struct{})
	return nil
}

func (worker *CloudflareWorker) Init() error {
	var err error

	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	worker.CloudflareIDByIP = make(map[string]map[string]string)
	worker.IPListByRemedy = make(map[string]cloudflare.IPList)
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
			// } else if zone.Plan.IsSubscribed && len(z.Remediation) > 1 {

			// }
			for _, remedy := range z.Remediation {
				worker.IPListByRemedy[remedy] = cloudflare.IPList{Name: worker.Account.IPListPrefix + remedy}
			}
		} else {
			return fmt.Errorf("account %s doesn't have access to one %s", worker.Account.ID, z.ID)
		}
	}
	worker.AddIPs.BanSet = make(map[string]struct{})
	worker.AddIPs.JSChallengeSet = make(map[string]struct{})
	worker.AddIPs.ChallengeSet = make(map[string]struct{})

	worker.RemoveIPs.BanSet = make(map[string]struct{})
	worker.RemoveIPs.JSChallengeSet = make(map[string]struct{})
	worker.RemoveIPs.ChallengeSet = make(map[string]struct{})

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
		case "IP":
			switch *decision.Type {
			case "ban":
				worker.AddIPs.BanSet[*decision.Value] = struct{}{}

			case "captcha":
				worker.AddIPs.ChallengeSet[*decision.Value] = struct{}{}

			case "js_challenge":
				worker.AddIPs.JSChallengeSet[*decision.Value] = struct{}{}
			}

		case "COUNTRY":
			expr := fmt.Sprintf(`ip.geoip.country eq "%s"`, *decision.Value)
			worker.AddCountryBans = append(worker.AddCountryBans, expr)

		case "AS":
			worker.AddASBans = append(worker.AddASBans, *decision.Value)

		}
	}
	for _, decision := range streamDecision.Deleted {
		switch scope := strings.ToUpper(*decision.Scope); scope {
		case "IP":
			switch *decision.Type {
			case "ban":
				worker.RemoveIPs.BanSet[*decision.Value] = struct{}{}

			case "captcha":
				worker.RemoveIPs.ChallengeSet[*decision.Value] = struct{}{}

			case "js_challenge":
				worker.RemoveIPs.JSChallengeSet[*decision.Value] = struct{}{}
			}

		case "COUNTRY":
			expr := fmt.Sprintf(`ip.geoip.country eq "%s"`, *decision.Value)
			worker.RemoveCountryBans = append(worker.RemoveCountryBans, expr)

		case "AS":
			expr := fmt.Sprintf("ip.geoip.asnum eq %s", *decision.Value)
			worker.RemoveASBans = append(worker.RemoveASBans, expr)
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
		for _, ASBan := range worker.AddASBans {
			expression := fmt.Sprintf("ip.geoip.asnum eq %s", ASBan)
			if _, existsInRuleSet := ruleSet[expression]; !existsInRuleSet {
				ASBans = append(ASBans, cloudflare.FirewallRule{
					Filter:      cloudflare.Filter{Expression: expression},
					Description: "CrowdSec AS Ban",
					Action:      "challenge",
					// Action:      zone.Remediation,
				})
				ruleSet[expression] = struct{}{}
			} else {
				zoneLogger.Debugf("rule with expression %s already exists", expression)
			}
		}
		if len(ASBans) > 0 {
			zoneLogger.Infof("sending %d AS bans", len(ASBans))
			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, ASBans)
			if err != nil {
				worker.Logger.Error(err)
				return err
			}
		}
	}
	worker.AddASBans = make([]string, 0)
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
		if len(worker.RemoveASBans) > 0 {
			zoneLogger.Infof("deleted %d AS bans", len(worker.RemoveASBans))
		}

	}
	worker.RemoveASBans = make([]string, 0)
	return nil

}

// func (worker *CloudflareWorker) SendCountryBans() error {
// 	for _, zone := range worker.Account.Zones {
// 		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
// 		countryBans := make([]cloudflare.FirewallRule, 0)

// 		//This set is used to ensure we don't send dups
// 		countryBanSet := make(map[string]struct{})
// 		for _, countryBan := range worker.AddCountryBans {
// 			if _, ok := countryBanSet[countryBan]; ok {
// 				continue
// 			}
// 			countryBanSet[countryBan] = struct{}{}
// 			err := worker.deleteRulesContainingString(countryBan, []string{zone.ID})
// 			if err != nil {
// 				return err
// 			}
// 			err = worker.deleteFiltersContainingString(countryBan, []string{zone.ID})
// 			if err != nil {
// 				return err
// 			}
// 			countryBans = append(countryBans, cloudflare.FirewallRule{
// 				Description: "Country Ban by CrowdSec",
// 				Filter: cloudflare.Filter{
// 					Expression: countryBan,
// 				},
// 				Action: zone.Remediation,
// 			})

// 		}
// 		if len(countryBans) > 0 {
// 			_, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, countryBans)
// 			if err != nil {
// 				return err
// 			}
// 			zoneLogger.Infof("added %d country bans", len(countryBans))
// 		}
// 	}
// 	worker.AddCountryBans = make([]string, 0)
// 	return nil
// }

func (worker *CloudflareWorker) DeleteCountryBans() error {

	// cloudflare also provides API.DeleteFirewallRules to delete all the rules in one shot
	for _, countryBan := range worker.RemoveCountryBans {
		err := worker.deleteRulesContainingString(countryBan, extractZoneIDs(worker.Account.Zones))
		if err != nil {
			return err
		}
		err = worker.deleteFiltersContainingString(countryBan, extractZoneIDs(worker.Account.Zones))
		if err != nil {
			return err
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
			// TODO: all of the below functions can be grouped and ran in separate goroutines for better performance
			err := worker.AddNewIPs()
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
			// err = worker.SendASBans()
			// if err != nil {
			// 	return err
			// }
			// err = worker.DeleteASBans()
			// if err != nil {
			// 	return err
			// }

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("processing new and deleted decisions from crowdsec LAPI")
			worker.CollectLAPIStream(decisions)
		}
	}

}
