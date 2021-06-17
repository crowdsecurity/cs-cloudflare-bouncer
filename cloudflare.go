package main

import (
	"context"
	"fmt"
	"sort"
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

type IPListState struct {
	IPList   *cloudflare.IPList
	ItemByIP map[string]cloudflare.IPListItem
}

// one firewall rule per zone.
type CloudflareState struct {
	Action              string
	AccountID           string
	FilterIDByZoneID    map[string]string // this contains all the zone ID -> filter ID which represent this state
	CurrExpr            string
	IPListState         IPListState
	CountrySet          map[string]struct{}
	AutonomousSystemSet map[string]struct{}
}

func setToExprList(set map[string]struct{}, quotes bool) string {
	items := make([]string, len(set))
	i := 0
	for str := range set {
		if quotes {
			items[i] = fmt.Sprintf(`"%s"`, str)
		} else {
			items[i] = str
		}
		i++
	}
	sort.Strings(items)
	return fmt.Sprintf("{%s}", strings.Join(items, " "))
}

func allZonesHaveAction(zones []CloudflareZone, action string) bool {
	allSupport := true
	for _, zone := range zones {
		if _, allSupport = zone.ActionSet[action]; !allSupport {
			break
		}
	}
	return allSupport
}

func (cfState CloudflareState) computeExpression() string {
	var countryExpr, ASExpr, ipExpr string
	buff := make([]string, 0)

	if len(cfState.CountrySet) > 0 {
		countryExpr = fmt.Sprintf("(ip.geoip.country in %s)", setToExprList(cfState.CountrySet, true))
		buff = append(buff, countryExpr)
	}

	if len(cfState.AutonomousSystemSet) > 0 {
		ASExpr = fmt.Sprintf("(ip.geoip.asnum in %s)", setToExprList(cfState.AutonomousSystemSet, false))
		buff = append(buff, ASExpr)
	}

	if cfState.IPListState.IPList != nil {
		ipExpr = fmt.Sprintf("(ip.src in $%s)", cfState.IPListState.IPList.Name)
		buff = append(buff, ipExpr)
	}

	return strings.Join(buff, " or ")
}

// updates the expression for the state. Returns true if new rule is
// different than the previous rule.
func (cfState *CloudflareState) UpdateExpr() bool {
	computedExpr := cfState.computeExpression()
	isNew := computedExpr != cfState.CurrExpr
	cfState.CurrExpr = computedExpr
	return isNew
}

type CloudflareWorker struct {
	Logger                  *log.Entry
	Account                 CloudflareAccount
	ZoneLocks               []ZoneLock
	CloudflareStateByAction map[string]*CloudflareState
	Ctx                     context.Context
	LAPIStream              chan *models.DecisionsStreamResponse
	UpdatedState            chan map[string]*CloudflareState
	UpdateFrequency         time.Duration
	NewIPDecisions          []*models.Decision
	ExpiredIPDecisions      []*models.Decision
	NewASDecisions          []*models.Decision
	ExpiredASDecisions      []*models.Decision
	NewCountryDecisions     []*models.Decision
	ExpiredCountryDecisions []*models.Decision
	API                     cloudflareAPI
	Wg                      *sync.WaitGroup
}

type cloudflareAPI interface {
	Filters(ctx context.Context, zoneID string, pageOpts cloudflare.PaginationOptions) ([]cloudflare.Filter, error)
	ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error)
	CreateIPList(ctx context.Context, name string, desc string, typ string) (cloudflare.IPList, error)
	DeleteIPList(ctx context.Context, id string) (cloudflare.IPListDeleteResponse, error)
	ListIPLists(ctx context.Context) ([]cloudflare.IPList, error)
	CreateFirewallRules(ctx context.Context, zone string, rules []cloudflare.FirewallRule) ([]cloudflare.FirewallRule, error)
	DeleteFirewallRules(ctx context.Context, zoneID string, firewallRuleIDs []string) error
	FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error)
	CreateIPListItems(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) ([]cloudflare.IPListItem, error)
	DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) ([]cloudflare.IPListItem, error)
	DeleteFilters(ctx context.Context, zoneID string, filterIDs []string) error
	UpdateFilters(ctx context.Context, zoneID string, filters []cloudflare.Filter) ([]cloudflare.Filter, error)
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
	tmpDefaulted := make([]*models.Decision, 0)
	for _, decision := range decisions {
		action := CloudflareActionByDecisionType[*decision.Type]
		if _, ok := decisionValueSet[*decision.Value]; ok {
			// dup
			continue
		}
		if action == "" {
			// unsupported decision type, ignore this if in case decision with supported action
			// for the same decision value is present.
			tmpDefaulted = append(tmpDefaulted, decision)
			continue
		} else {
			decisionValueSet[*decision.Value] = struct{}{}
		}
		decisonsByAction[action] = append(decisonsByAction[action], decision)
	}
	defaulted := make([]*models.Decision, 0)
	for _, decision := range tmpDefaulted {
		if _, ok := decisionValueSet[*decision.Value]; ok {
			// dup
			continue
		}
		defaulted = append(defaulted, decision)
	}
	decisonsByAction["defaulted"] = defaulted
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

	for _, state := range worker.CloudflareStateByAction {
		IPList := state.IPListState.IPList
		id := worker.getIPListID(IPList.Name, IPLists) // requires ip list name
		if id == nil {
			worker.Logger.Infof("ip list %s does not exists", IPList.Name)
			continue
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
	if err != nil {
		return err
	}

	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}

	worker.Logger.Debugf("found %d zones on this account", len(zones))
	err = worker.deleteRulesContainingString(fmt.Sprintf("$%s", IPListName), zoneIDs)
	if err != nil {
		return err
	}
	// A Filter can exist on it's own, they are not visible on UI, they are API only.
	// Clear these Filters.
	err = worker.deleteFiltersContainingString(fmt.Sprintf("$%s", IPListName), zoneIDs)
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

	for action, state := range worker.CloudflareStateByAction {
		ipList := *state.IPListState.IPList
		tmp, err := worker.API.CreateIPList(worker.Ctx, ipList.Name, fmt.Sprintf("%s IP list by crowdsec", action), "ip")
		if err != nil {
			return err
		}
		*worker.CloudflareStateByAction[action].IPListState.IPList = tmp
		worker.CloudflareStateByAction[action].IPListState.ItemByIP = make(map[string]cloudflare.IPListItem)
		worker.CloudflareStateByAction[action].UpdateExpr()

	}
	return nil
}

func (worker *CloudflareWorker) SetUpRules() error {
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for _, action := range zone.Actions {
			ruleExpression := worker.CloudflareStateByAction[action].CurrExpr
			firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: ruleExpression}, Action: action, Description: fmt.Sprintf("CrowdSec %s rule", action)}}
			rule, err := worker.API.CreateFirewallRules(worker.Ctx, zone.ID, firewallRules)
			if err != nil {
				worker.Logger.WithFields(log.Fields{"zone_id": zone.ID}).Errorf("error %s in creating firewall rule %s", err.Error(), ruleExpression)
				return err
			}
			worker.CloudflareStateByAction[action].FilterIDByZoneID[zone.ID] = rule[0].Filter.ID
		}
		zoneLogger.Info("firewall rules created")
	}
	worker.Logger.Info("setup of firewall rules complete")
	return nil
}

func (worker *CloudflareWorker) AddNewIPs() error {
	// IP decisions are applied at account level
	decisonsByAction := classifyDecisionsByAction(worker.NewIPDecisions)
	for action, decisions := range decisonsByAction {
		// In case some zones support this action and others don't,  we put this in account's default action.
		if !allZonesHaveAction(worker.Account.Zones, action) {
			if worker.Account.DefaultAction == "none" {
				worker.Logger.Debugf("dropping IP decisions with unsupported action %s", action)
				continue
			}
			action = worker.Account.DefaultAction
			worker.Logger.Debugf("ip action defaulted to %s", action)
		}
		state := worker.CloudflareStateByAction[action]
		newIPs := make([]cloudflare.IPListItemCreateRequest, 0)
		for _, decision := range decisions {
			// check if ip already exists in state. Send if not exists.
			ip := normalizeIP(*decision.Value)
			if _, ok := state.IPListState.ItemByIP[ip]; !ok {
				newIPs = append(newIPs, cloudflare.IPListItemCreateRequest{
					IP:      ip,
					Comment: *decision.Scenario,
				})
				worker.CloudflareStateByAction[action].IPListState.IPList.NumItems++
			}
		}
		if len(newIPs) > 0 {
			items, err := worker.API.CreateIPListItems(worker.Ctx, state.IPListState.IPList.ID, newIPs)
			if err != nil {
				return err
			}
			worker.Logger.Infof("banned %d IPs", len(newIPs))
			for _, item := range items {
				worker.CloudflareStateByAction[action].IPListState.ItemByIP[item.IP] = item
			}
		}

	}
	go func() { worker.UpdatedState <- worker.CloudflareStateByAction }()
	worker.NewIPDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteIPs() error {
	// IP decisions are applied at account level
	decisonsByAction := classifyDecisionsByAction(worker.ExpiredIPDecisions)
	for action, decisions := range decisonsByAction {
		// In case some zones support this action and others don't,  we put this in account's default action.
		if !allZonesHaveAction(worker.Account.Zones, action) {
			if worker.Account.DefaultAction == "none" {
				worker.Logger.Debugf("dropping IP delete decisions with unsupported action %s", action)
				continue
			}
			action = worker.Account.DefaultAction
			worker.Logger.Debugf("ip delete action defaulted to %s", action)

		}
		state := worker.CloudflareStateByAction[action]
		deleteIPs := cloudflare.IPListItemDeleteRequest{Items: make([]cloudflare.IPListItemDeleteItemRequest, 0)}
		for _, decision := range decisions {
			// delete only if ip already exists in state.
			ip := normalizeIP(*decision.Value)
			if item, ok := state.IPListState.ItemByIP[ip]; ok {
				deleteIPs.Items = append(deleteIPs.Items, cloudflare.IPListItemDeleteItemRequest{ID: item.ID})
			}
		}

		if len(deleteIPs.Items) > 0 {
			_, err := worker.API.DeleteIPListItems(worker.Ctx, state.IPListState.IPList.ID, deleteIPs)
			if err != nil {
				return err
			}
			worker.CloudflareStateByAction[action].IPListState.IPList.NumItems -= len(deleteIPs.Items)
			ipByID := make(map[string]string)
			for ip, item := range worker.CloudflareStateByAction[action].IPListState.ItemByIP {
				ipByID[item.ID] = ip
			}
			for _, item := range deleteIPs.Items {
				delete(worker.CloudflareStateByAction[action].IPListState.ItemByIP, ipByID[item.ID])
			}
		}

	}
	go func() { worker.UpdatedState <- worker.CloudflareStateByAction }()
	worker.ExpiredIPDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) Init() error {

	defer worker.Wg.Done()
	defer func() { go func() { worker.UpdatedState <- worker.CloudflareStateByAction }() }()

	var err error

	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	worker.NewIPDecisions = make([]*models.Decision, 0)
	worker.ExpiredIPDecisions = make([]*models.Decision, 0)

	if worker.API == nil { // this for easy swapping during tests
		worker.API, err = cloudflare.NewWithAPIToken(worker.Account.Token, cloudflare.UsingAccount(worker.Account.ID))
	}
	worker.Logger.Debug("setup of API complete")

	if len(worker.CloudflareStateByAction) != 0 {
		// no  need to  setup ip lists and rules.
		return nil
	}

	worker.CloudflareStateByAction = make(map[string]*CloudflareState)

	zones, err := worker.API.ListZones(worker.Ctx)
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}
	zoneByID := make(map[string]cloudflare.Zone)
	for _, zone := range zones {
		zoneByID[zone.ID] = zone
	}

	for _, z := range worker.Account.Zones {
		if zone, ok := zoneByID[z.ID]; ok {
			// FIXME this is probably wrong.
			if !zone.Plan.IsSubscribed && len(z.Actions) > 1 {
				return fmt.Errorf("zone %s 's plan doesn't support multiple actionss", z.ID)
			}

			for _, action := range z.Actions {
				listName := fmt.Sprintf("%s_%s", worker.Account.IPListPrefix, action)
				worker.CloudflareStateByAction[action] = &CloudflareState{
					AccountID:   worker.Account.ID,
					Action:      action,
					IPListState: IPListState{IPList: &cloudflare.IPList{Name: listName}, ItemByIP: make(map[string]cloudflare.IPListItem)},
				}
				worker.CloudflareStateByAction[action].FilterIDByZoneID = make(map[string]string)
				worker.CloudflareStateByAction[action].CountrySet = make(map[string]struct{})
				worker.CloudflareStateByAction[action].AutonomousSystemSet = make(map[string]struct{})

			}
		} else {
			return fmt.Errorf("account %s doesn't have access to one %s", worker.Account.ID, z.ID)
		}
	}

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
	decisionsByAction := classifyDecisionsByAction(worker.NewASDecisions)
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for action, decisions := range decisionsByAction {
			if _, spAction := zone.ActionSet[action]; action == "defaulted" || !spAction {
				if action != "defaulted" {
					zoneLogger.Debugf("defaulting %s action to %s action", action, zone.Actions[0])
				}
				action = zone.Actions[0]
			}
			for _, decision := range decisions {
				if _, ok := worker.CloudflareStateByAction[action].AutonomousSystemSet[*decision.Value]; !ok {
					zoneLogger.Debugf("found new AS ban for %s", *decision.Value)
					worker.CloudflareStateByAction[action].AutonomousSystemSet[*decision.Value] = struct{}{}
				}
			}
		}
	}
	worker.NewASDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteASBans() error {
	decisionsByAction := classifyDecisionsByAction(worker.ExpiredASDecisions)
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for action, decisions := range decisionsByAction {
			if _, spAction := zone.ActionSet[action]; action == "defaulted" || !spAction {
				if action != "defaulted" {
					zoneLogger.Debugf("defaulting %s action to %s action", action, zone.Actions[0])
				}
				action = zone.Actions[0]
			}
			for _, decision := range decisions {
				if _, ok := worker.CloudflareStateByAction[action].AutonomousSystemSet[*decision.Value]; ok {
					zoneLogger.Debugf("found expired AS ban for %s", *decision.Value)
					delete(worker.CloudflareStateByAction[action].AutonomousSystemSet, *decision.Value)
				}
			}
		}
	}
	worker.ExpiredASDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) SendCountryBans() error {
	decisionsByAction := classifyDecisionsByAction(worker.NewCountryDecisions)
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for action, decisions := range decisionsByAction {
			if _, spAction := zone.ActionSet[action]; action == "defaulted" || !spAction {
				if action != "defaulted" {
					zoneLogger.Debugf("defaulting %s action to %s action", action, zone.Actions[0])
				}
				action = zone.Actions[0]
			}
			for _, decision := range decisions {
				if _, ok := worker.CloudflareStateByAction[action].CountrySet[*decision.Value]; !ok {
					zoneLogger.Debugf("found new country ban for %s", *decision.Value)
					worker.CloudflareStateByAction[action].CountrySet[*decision.Value] = struct{}{}
				}
			}
		}
	}
	worker.NewCountryDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteCountryBans() error {
	decisionsByAction := classifyDecisionsByAction(worker.ExpiredCountryDecisions)
	for _, zone := range worker.Account.Zones {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for action, decisions := range decisionsByAction {
			if _, spAction := zone.ActionSet[action]; action == "defaulted" || !spAction {
				if action != "defaulted" {
					zoneLogger.Debugf("defaulting %s action to %s action", action, zone.Actions[0])
				}
				action = zone.Actions[0]
			}
			for _, decision := range decisions {
				if _, ok := worker.CloudflareStateByAction[action].CountrySet[*decision.Value]; ok {
					zoneLogger.Debugf("found expired country ban for %s", *decision.Value)
					delete(worker.CloudflareStateByAction[action].CountrySet, *decision.Value)
				}
			}
		}
	}
	worker.ExpiredCountryDecisions = make([]*models.Decision, 0)
	return nil
}
func (worker *CloudflareWorker) UpdateRules() error {
	stateIsNew := false
	for action, state := range worker.CloudflareStateByAction {
		if !worker.CloudflareStateByAction[action].UpdateExpr() {
			// expression is still same, why bother.
			worker.Logger.Infof("rule for %s action is unchanged", action)
			continue
		}
		stateIsNew = true
		for _, zone := range worker.Account.Zones {
			zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
			updatedFilters := make([]cloudflare.Filter, 0)
			if _, ok := zone.ActionSet[action]; ok {
				// check whether this action is supported by this zone
				updatedFilters = append(updatedFilters, cloudflare.Filter{ID: state.FilterIDByZoneID[zone.ID], Expression: state.CurrExpr})
			}
			if len(updatedFilters) > 0 {
				zoneLogger.Infof("updating %d rules", len(updatedFilters))
				_, err := worker.API.UpdateFilters(worker.Ctx, zone.ID, updatedFilters)
				if err != nil {
					return err
				}
			} else {
				zoneLogger.Debug("rules are same")
			}
		}
	}
	if stateIsNew {
		go func() { worker.UpdatedState <- worker.CloudflareStateByAction }()
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

			if len(worker.ExpiredCountryDecisions) > 0 {
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
			err := worker.UpdateRules()
			if err != nil {
				worker.Logger.Error(err)
				return err
			}

		case decisions := <-worker.LAPIStream:
			worker.Logger.Info("collecting decisions from LAPI")
			worker.CollectLAPIStream(decisions)

		}
	}

}
