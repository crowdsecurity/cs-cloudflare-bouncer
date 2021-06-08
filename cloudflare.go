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
	IPListByAction          map[string]cloudflare.IPList
	UpdateFrequency         time.Duration
	CloudflareIDByIP        map[string]string // "ip_list_id" -> "ip" ->"cf_id"
	NewIPDecisions          []*models.Decision
	ExpiredIPDecisions      []*models.Decision
	NewASDecisions          []*models.Decision
	ExpiredASDecisions      []*models.Decision
	NewCountryDecisions     []*models.Decision
	ExpiredCountryDecisions []*models.Decision
	API                     cloudflareAPI
	Wg                      *sync.WaitGroup
}

func extractZoneIDs(zones []CloudflareZone) []string {
	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}
	return zoneIDs
}

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}

func normalizeIP(ip string) string {
	if strings.Count(ip, ":") <= 1 {
		// it is a ipv4
		return ip
	}

	comps := strings.Split(ip, "::")
	// comps[0] would be the IP part and comps[1] (if present) would be the either remaining IP or CIDR
	// we don't care about remaining IP because last digits can be changed.
	ipBlocks := strings.Split(comps[0], ":")
	blockCount := min(4, len(ipBlocks))
	cidr := blockCount * 16
	return strings.Join(ipBlocks[:blockCount], ":") + fmt.Sprintf("::/%d", cidr)
}

// Helper which removes dups and splits decisions according to their action.
// Decisions with unsupported action are ignored
func classifyDecisionsByAction(decisions []*models.Decision) map[string][]*models.Decision {
	decisionValueSet := make(map[string]struct{})
	decisonsByAction := make(map[string][]*models.Decision)
	for _, decision := range decisions {
		action := CloudflareActionByDecisionType[*decision.Type]
		if action == "" {
			// unsupported decision type
			continue
		}
		if _, ok := decisionValueSet[*decision.Value]; ok {
			// dup
			continue
		}
		decisonsByAction[action] = append(decisonsByAction[action], decision)
		decisionValueSet[*decision.Value] = struct{}{}
	}
	return decisonsByAction
}

func (worker *CloudflareWorker) getMutexByZoneID(zoneID string) (*sync.Mutex, error) {
	for _, zoneLock := range worker.ZoneLocks {
		if zoneLock.ZoneID == zoneID {
			return zoneLock.Lock, nil
		}
	}
	return nil, fmt.Errorf("zone lock for the zone id %s not found", zoneID)
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

	for _, IPList := range worker.IPListByAction {
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

	for remedy, IPList := range worker.IPListByAction {
		worker.IPListByAction[remedy], err = worker.API.CreateIPList(worker.Ctx, IPList.Name, fmt.Sprintf("%s IP list by crowdsec", remedy), "ip")
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
			ruleExpression := fmt.Sprintf("ip.src in $%s", worker.IPListByAction[remedy].Name)
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
	decisonsByAction := classifyDecisionsByAction(worker.NewIPDecisions)
	for action, IPList := range worker.IPListByAction {
		if _, ok := decisonsByAction[action]; !ok {
			continue
		}
		addIPs := make([]cloudflare.IPListItemCreateRequest, 0)
		for _, decision := range decisonsByAction[action] {
			addIPs = append(addIPs, cloudflare.IPListItemCreateRequest{
				IP:      normalizeIP(*decision.Value),
				Comment: *decision.Scenario,
			})
		}
		items, err := worker.API.CreateIPListItems(worker.Ctx, IPList.ID, addIPs)
		if err != nil {
			return err
		}
		worker.Logger.Infof("banned %d IPs", len(addIPs))
		for _, item := range items {
			worker.CloudflareIDByIP[item.ID] = item.IP
		}
	}
	worker.NewIPDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteIPs() error {
	decisonsByAction := classifyDecisionsByAction(worker.ExpiredIPDecisions)
	for action, IPList := range worker.IPListByAction {
		if _, ok := decisonsByAction[action]; !ok {
			continue
		}
		deleteIPs := cloudflare.IPListItemDeleteRequest{}
		for _, IPDeletedecision := range decisonsByAction[action] {
			if id, ok := worker.CloudflareIDByIP[*IPDeletedecision.Value]; ok {
				deleteIPs.Items = append(deleteIPs.Items, cloudflare.IPListItemDeleteItemRequest{ID: id})
			}
		}
		if len(deleteIPs.Items) > 0 {
			_, err := worker.API.DeleteIPListItems(worker.Ctx, IPList.ID, deleteIPs)
			if err != nil {
				return err
			}
			worker.Logger.Infof("removed %d IP bans", len(deleteIPs.Items))
		}
	}
	worker.ExpiredIPDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) Init() error {

	defer worker.Wg.Done()
	var err error

	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	worker.IPListByAction = make(map[string]cloudflare.IPList)
	worker.NewIPDecisions = make([]*models.Decision, 0)
	worker.ExpiredIPDecisions = make([]*models.Decision, 0)
	worker.CloudflareIDByIP = make(map[string]string)

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

			for _, action := range z.Remediation {
				listName := fmt.Sprintf("%s_%s", worker.Account.IPListPrefix, action)
				worker.IPListByAction[action] = cloudflare.IPList{Name: listName}
			}
		} else {
			return fmt.Errorf("account %s doesn't have access to one %s", worker.Account.ID, z.ID)
		}
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
	return err
}

func (worker *CloudflareWorker) CleanUp() {
	worker.Logger.Error("stopping")
}

func (worker *CloudflareWorker) CollectLAPIStream(streamDecision *models.DecisionsStreamResponse) {
	worker.Logger.Infof("received %d decisions, %d are new , %d are expired",
		len(streamDecision.New)+len(streamDecision.Deleted), len(streamDecision.New), len(streamDecision.Deleted),
	)

	for _, decision := range streamDecision.New {
		catched := true
		*decision.Type = strings.ToLower(*decision.Type)
		switch scope := strings.ToUpper(*decision.Scope); scope {
		case "IP", "RANGE":
			worker.NewIPDecisions = append(worker.NewIPDecisions, decision)

		case "COUNTRY":
			worker.NewCountryDecisions = append(worker.NewCountryDecisions, decision)

		case "AS":
			worker.NewASDecisions = append(worker.NewASDecisions, decision)

		default:
			catched = false
		}
		if catched {
			worker.Logger.Debugf("received new decision with scope=%s, type=%s, value=%s", *decision.Scope, *decision.Type, *decision.Value)
		} else {
			// TODO: once we start explictly specifying the decisions we're interested in, this won't be needed
			worker.Logger.Debugf("ignored new decision with scope=%s, type=%s, value=%s", *decision.Scope, *decision.Type, *decision.Value)
		}

	}

	for _, decision := range streamDecision.Deleted {
		catched := true
		switch scope := strings.ToUpper(*decision.Scope); scope {
		case "IP", "RANGE":
			worker.ExpiredIPDecisions = append(worker.ExpiredIPDecisions, decision)

		case "COUNTRY":
			worker.ExpiredCountryDecisions = append(worker.ExpiredCountryDecisions, decision)

		case "AS":
			worker.ExpiredASDecisions = append(worker.ExpiredASDecisions, decision)

		default:
			catched = false
		}

		if catched {
			worker.Logger.Debugf("received expired decision with scope=%s, type=%s, value=%s", *decision.Scope, *decision.Type, *decision.Value)
		} else {
			// TODO: once we start explictly specifying the decisions we're interested in, this won't be needed
			worker.Logger.Debugf("ignored expired decision with scope=%s, type=%s, value=%s", *decision.Scope, *decision.Type, *decision.Value)
		}
	}

}

func (worker *CloudflareWorker) SendASBans() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		rules, err := worker.API.Filters(worker.Ctx, zone.ID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}

		ruleSet := make(map[string]struct{})
		for _, rule := range rules {
			ruleSet[rule.Expression] = struct{}{}
		}

		ASBans := make([]cloudflare.FirewallRule, 0)
		for _, ASBanDecision := range worker.NewASDecisions {
			expr := fmt.Sprintf("ip.geoip.asnum eq %s", *ASBanDecision.Value)
			var action string
			defaulted := false
			if _, ok := CloudflareActionByDecisionType[*ASBanDecision.Type]; !ok {
				action = zone.Remediation[0]
				defaulted = true
			} else {
				action = CloudflareActionByDecisionType[*ASBanDecision.Type]
			}
			rule := cloudflare.FirewallRule{
				Filter:      cloudflare.Filter{Expression: expr},
				Description: "triggered " + *ASBanDecision.Scenario,
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
	worker.Logger.Info("waiting for other workers")
	worker.Wg.Wait()
	ticker := time.NewTicker(worker.UpdateFrequency)
	for {
		select {
		case <-ticker.C:
			// TODO: all of the below functions can be grouped and ran in separate goroutines for better performance

			if len(worker.ExpiredIPDecisions) > 0 {
				worker.Logger.Debug("processing expired IP  decisions")
				err := worker.DeleteIPs()
				if err != nil {
					return err
				}
			} else {
				worker.Logger.Debug("no new expired IP  decisions")
			}

			if len(worker.NewIPDecisions) > 0 {
				worker.Logger.Debug("processing new IP decisions")
				err = worker.AddNewIPs()
				if err != nil {
					return err
				}
			} else {
				worker.Logger.Debug("no new IP decisions")
			}

			if len(worker.ExpiredCountryDecisions) > 1 {
				worker.Logger.Debug("processing expired country decisions")
				err = worker.DeleteCountryBans()
				if err != nil {
					return err
				}
			} else {
				worker.Logger.Debug("no expired country decisions")
			}

			if len(worker.NewCountryDecisions) > 0 {
				worker.Logger.Debug("processing new country decisions")
				err = worker.SendCountryBans()
				if err != nil {
					return err
				}
			} else {
				worker.Logger.Debug("no new country decisions")
			}

			if len(worker.ExpiredASDecisions) > 0 {
				worker.Logger.Debug("processing expired AS decisions")
				err = worker.DeleteASBans()
				if err != nil {
					return err
				}
			} else {
				worker.Logger.Debug("no expired AS decisions")
			}

			if len(worker.NewASDecisions) > 0 {
				worker.Logger.Debug("processing new AS decisions")
				err = worker.SendASBans()
				if err != nil {
					return err
				}

			} else {
				worker.Logger.Debug("no new AS decisions")
			}

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("collecting decisions from LAPI")
			worker.CollectLAPIStream(decisions)

		}
	}

}
