package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	log "github.com/sirupsen/logrus"
)

const CallsPerSecondLimit uint32 = 4

var TotalIPListCapacity int = 10000

var CloudflareActionByDecisionType = map[string]string{
	"captcha":      "challenge",
	"ban":          "block",
	"js_challenge": "js_challenge",
}

var ResponseTime prometheus.Histogram = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "response_time",
	Help:    "response time by cloudflare",
	Buckets: prometheus.LinearBuckets(0, 100, 50),
},
)

var TotalAPICalls prometheus.Counter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cloudflare_api_calls",
	Help: "The total number of API calls to cloudflare made by CrowdSec bouncer",
},
)

type ZoneLock struct {
	Lock   *sync.Mutex
	ZoneID string
}

type IPSetItem struct {
	CreatedAt time.Time
}

type IPListState struct {
	IPList *cloudflare.IPList
	IPSet  map[string]IPSetItem `json:"-"`
}

// one firewall rule per state.
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

func allZonesHaveAction(zones []ZoneConfig, action string) bool {
	allSupport := true
	for _, zone := range zones {
		if _, allSupport = zone.ActionSet[action]; !allSupport {
			break
		}
	}
	return allSupport
}

func calculateIPSetDiff(setA map[string]IPSetItem, setB map[string]IPSetItem) (int, int) {
	exclusiveToA := 0
	exclusiveToB := 0
	for item := range setA {
		if _, ok := setB[item]; !ok {
			exclusiveToA++
		}
	}

	for item := range setB {
		if _, ok := setA[item]; !ok {
			exclusiveToB++
		}
	}
	return exclusiveToA, exclusiveToB
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
	APILogger               *log.Logger
	Account                 AccountConfig
	ZoneLocks               []ZoneLock
	Zones                   []cloudflare.Zone
	FirewallRulesByZoneID   map[string]*[]cloudflare.FirewallRule
	CFStateByAction         map[string]*CloudflareState
	Ctx                     context.Context
	LAPIStream              chan *models.DecisionsStreamResponse
	UpdateFrequency         time.Duration
	NewIPDecisions          []*models.Decision
	ExpiredIPDecisions      []*models.Decision
	NewASDecisions          []*models.Decision
	ExpiredASDecisions      []*models.Decision
	NewCountryDecisions     []*models.Decision
	ExpiredCountryDecisions []*models.Decision
	API                     cloudflareAPI
	Count                   prometheus.Counter
	tokenCallCount          *uint32
}

// this is useful for testing allowing us to mock it.
type cloudflareAPI interface {
	Filters(ctx context.Context, zoneID string, pageOpts cloudflare.PaginationOptions) ([]cloudflare.Filter, error)
	ListZones(ctx context.Context, z ...string) ([]cloudflare.Zone, error)
	CreateIPList(ctx context.Context, name string, desc string, typ string) (cloudflare.IPList, error)
	DeleteIPList(ctx context.Context, id string) (cloudflare.IPListDeleteResponse, error)
	ListIPLists(ctx context.Context) ([]cloudflare.IPList, error)
	CreateFirewallRules(ctx context.Context, zone string, rules []cloudflare.FirewallRule) ([]cloudflare.FirewallRule, error)
	DeleteFirewallRules(ctx context.Context, zoneID string, firewallRuleIDs []string) error
	FirewallRules(ctx context.Context, zone string, opts cloudflare.PaginationOptions) ([]cloudflare.FirewallRule, error)
	DeleteFilters(ctx context.Context, zoneID string, filterIDs []string) error
	UpdateFilters(ctx context.Context, zoneID string, filters []cloudflare.Filter) ([]cloudflare.Filter, error)
	ReplaceIPListItemsAsync(ctx context.Context, id string, items []cloudflare.IPListItemCreateRequest) (cloudflare.IPListItemCreateResponse, error)
	GetIPListBulkOperation(ctx context.Context, id string) (cloudflare.IPListBulkOperation, error)
	ListIPListItems(ctx context.Context, id string) ([]cloudflare.IPListItem, error)
	DeleteIPListItems(ctx context.Context, id string, items cloudflare.IPListItemDeleteRequest) (
		[]cloudflare.IPListItem, error)
}

func normalizeDecisionValue(value string) string {
	if strings.Count(value, ":") <= 1 {
		// it is a ipv4
		// Cloudflare does not allow duplicates, but LAPI can send us "duplicates" (e.g. 1.2.3.4 and 1.2.3.4/32)
		if strings.HasSuffix(value, "/32") {
			return value[:len(value)-3]
		}
		return value
	}
	var address *net.IPNet
	_, address, err := net.ParseCIDR(value)
	if err != nil {
		// doesn't have mask, we add one then.
		_, address, _ = net.ParseCIDR(value + "/64")
		// this would never cause error because crowdsec already validates IP
	}

	if ones, _ := address.Mask.Size(); ones < 64 {
		return address.String()
	}
	address.Mask = net.CIDRMask(64, 128)
	return address.String()
}

// Helper which removes dups and splits decisions according to their action.
// Decisions with unsupported action are ignored
func dedupAndClassifyDecisionsByAction(decisions []*models.Decision) map[string][]*models.Decision {
	decisionValueSet := make(map[string]struct{})
	decisonsByAction := make(map[string][]*models.Decision)
	tmpDefaulted := make([]*models.Decision, 0)
	for _, decision := range decisions {
		*decision.Value = normalizeDecisionValue(*decision.Value)
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

// getters
func (worker *CloudflareWorker) getMutexByZoneID(zoneID string) (*sync.Mutex, error) {
	for _, zoneLock := range worker.ZoneLocks {
		if zoneLock.ZoneID == zoneID {
			return zoneLock.Lock, nil
		}
	}
	return nil, fmt.Errorf("zone lock for the zone id %s not found", zoneID)
}

func (worker *CloudflareWorker) getAPI() cloudflareAPI {
	atomic.AddUint32(worker.tokenCallCount, 1)
	if *worker.tokenCallCount > CallsPerSecondLimit {
		time.Sleep(time.Second)
	}
	TotalAPICalls.Inc()
	return worker.API
}

func (worker *CloudflareWorker) deleteRulesContainingStringFromZoneIDs(str string, zonesIDs []string) error {
	for _, zoneID := range zonesIDs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneID})
		zoneLock, err := worker.getMutexByZoneID(zoneID)
		if err == nil {
			zoneLock.Lock()
			defer zoneLock.Unlock()
		}
		rules, err := worker.getAPI().FirewallRules(worker.Ctx, zoneID, cloudflare.PaginationOptions{})
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
			err = worker.getAPI().DeleteFirewallRules(worker.Ctx, zoneID, deleteRules)
			if err != nil {
				return err
			}
			zoneLogger.Infof("deleted %d firewall rules containing the string %s", len(deleteRules), str)
		}

	}
	return nil
}

func getIPListNameWithPrefixForAction(prefix string, action string) string {
	return fmt.Sprintf("%s_%s", prefix, action)
}

func (worker *CloudflareWorker) importExistingIPLists() error {
	IPLists, err := worker.getAPI().ListIPLists(worker.Ctx)
	if err != nil {
		return err
	}
	for action := range worker.CFStateByAction {
		for _, IPList := range IPLists {
			if IPList.Name != getIPListNameWithPrefixForAction(worker.Account.IPListPrefix, action) {
				continue
			}
			worker.Logger.Infof("using existing  ip list %s", IPList.Name)
			worker.CFStateByAction[action].IPListState.IPList = &IPList
			if items, err := worker.getAPI().ListIPListItems(worker.Ctx, IPList.ID); err == nil {
				for _, item := range items {
					if item.CreatedOn != nil {
						worker.CFStateByAction[action].IPListState.IPSet[item.IP] = IPSetItem{
							CreatedAt: *item.CreatedOn,
						}
					}
				}
			}
			// TODO we can also import existing content here, to exclude user's custom banned IPs.
		}
	}
	return nil
}

func (worker *CloudflareWorker) importRulesAndFiltersForExistingIPList(IPListName string) error {
	for _, zone := range worker.Account.ZoneConfigs {
		rules, err := worker.cachedFirewallRules(zone.ID)
		if err != nil {
			return err
		}
		for action, state := range worker.CFStateByAction {
			for _, rule := range rules {
				if state == nil || state.IPListState.IPList == nil || state.IPListState.IPList.Name == "" {
					continue
				}
				if strings.Contains(rule.Description, fmt.Sprintf("CrowdSec %s rule", action)) &&
					strings.Contains(rule.Filter.Expression, state.IPListState.IPList.Name) {
					worker.Logger.WithField("zone_id", zone.ID).Infof("found existing rule for %s action", action)
					worker.CFStateByAction[action].FilterIDByZoneID[zone.ID] = rule.Filter.ID
					worker.CFStateByAction[action].CurrExpr = rule.Filter.Expression
				}
			}
		}

	}
	return nil
}

func (worker *CloudflareWorker) importExistingInfra() error {
	if err := worker.importExistingIPLists(); err != nil {
		return err
	}
	for _, state := range worker.CFStateByAction {
		if state.IPListState.IPList != nil {
			worker.importRulesAndFiltersForExistingIPList(state.IPListState.IPList.Name)
		}
	}
	return nil
}

func (worker *CloudflareWorker) deleteFiltersContainingStringFromZoneIDs(str string, zonesIDs []string) error {
	for _, zoneID := range zonesIDs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneID})
		zoneLock, err := worker.getMutexByZoneID(zoneID)
		if err == nil {
			zoneLock.Lock()
			defer zoneLock.Unlock()
		}
		filters, err := worker.getAPI().Filters(worker.Ctx, zoneID, cloudflare.PaginationOptions{})
		if err != nil {
			return err
		}
		deleteFilters := make([]string, 0)
		for _, filter := range filters {
			if strings.Contains(filter.Expression, str) {
				deleteFilters = append(deleteFilters, filter.ID)
				zoneLogger.Infof("deleting %s filter with expression %s", filter.ID, filter.Expression)
			}
		}

		if len(deleteFilters) > 0 {
			zoneLogger.Infof("deleting %d filters", len(deleteFilters))
			err = worker.getAPI().DeleteFilters(worker.Ctx, zoneID, deleteFilters)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

func (worker *CloudflareWorker) deleteExistingIPList() error {
	worker.Logger.Info("Getting all IP lists")
	IPLists, err := worker.getAPI().ListIPLists(worker.Ctx)
	if err != nil {
		return err
	}
	for _, IPList := range IPLists {
		if !strings.Contains(IPList.Description, "IP list by crowdsec") {
			continue
		}
		worker.Logger.Infof("removing %s ip list", IPList.Name)
		err = worker.removeIPListDependencies(IPList.Name)
		if err != nil {
			return err
		}

		worker.Logger.Infof("deleting ip list %s", IPList.Name)
		_, err = worker.getAPI().DeleteIPList(worker.Ctx, IPList.ID)
		if err != nil {
			return err
		}
	}
	return nil
}

// cached cachedListZones
func (worker *CloudflareWorker) cachedListZones() ([]cloudflare.Zone, error) {
	if len(worker.Zones) != 0 {
		return worker.Zones, nil
	}
	zones, err := worker.getAPI().ListZones(worker.Ctx)
	if err != nil {
		return nil, err
	}
	worker.Zones = zones
	return zones, nil
}

func (worker *CloudflareWorker) cachedFirewallRules(zoneID string) ([]cloudflare.FirewallRule, error) {
	if worker.FirewallRulesByZoneID[zoneID] != nil {
		return *worker.FirewallRulesByZoneID[zoneID], nil
	}
	rules, err := worker.getAPI().FirewallRules(worker.Ctx, zoneID, cloudflare.PaginationOptions{})
	if err != nil {
		return nil, err
	}
	worker.FirewallRulesByZoneID[zoneID] = &rules
	return rules, err
}

func (worker *CloudflareWorker) removeIPListDependencies(IPListName string) error {
	worker.Logger.Info("removing ip list dependencies")
	worker.Logger.Info("listing zones")
	zones, err := worker.cachedListZones()
	if err != nil {
		return err
	}

	zoneIDs := make([]string, len(zones))
	for i, zone := range zones {
		zoneIDs[i] = zone.ID
	}

	worker.Logger.Infof("found %d zones on this account", len(zones))
	worker.Logger.Infof("deleting rules containing $%s", IPListName)
	err = worker.deleteRulesContainingStringFromZoneIDs(fmt.Sprintf("$%s", IPListName), zoneIDs)
	if err != nil {
		return err
	}
	// A Filter can exist on it's own, they are not visible on UI, they are API only.
	// Clear these Filters.
	worker.Logger.Infof("deleting filters containing $%s", IPListName)
	err = worker.deleteFiltersContainingStringFromZoneIDs(fmt.Sprintf("$%s", IPListName), zoneIDs)
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

func (worker *CloudflareWorker) createMissingIPLists() error {
	// if IP list already exists don't create one
	for action := range worker.CFStateByAction {
		if worker.CFStateByAction[action].IPListState.IPList == nil {
			ipList, err := worker.getAPI().CreateIPList(
				worker.Ctx,
				fmt.Sprintf("%s_%s", worker.Account.IPListPrefix, action),
				fmt.Sprintf("%s IP list by crowdsec", action),
				"ip",
			)
			if err != nil {
				return err
			}
			worker.CFStateByAction[action].IPListState.IPList = &ipList
		}
		worker.CFStateByAction[action].IPListState.IPSet = make(map[string]IPSetItem)
		worker.CFStateByAction[action].UpdateExpr()
	}
	return nil
}

func (worker *CloudflareWorker) createMissingRules() error {
	for _, zone := range worker.Account.ZoneConfigs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
		for _, action := range zone.Actions {
			if worker.CFStateByAction[action].FilterIDByZoneID[zone.ID] != "" {
				zoneLogger.Info("skipping rule creation for " + action)
				continue
			}
			ruleExpression := worker.CFStateByAction[action].CurrExpr
			firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: ruleExpression}, Action: action, Description: fmt.Sprintf("CrowdSec %s rule", action)}}
			rule, err := worker.getAPI().CreateFirewallRules(worker.Ctx, zone.ID, firewallRules)
			if err != nil {
				worker.Logger.WithFields(log.Fields{"zone_id": zone.ID}).Errorf("error %s in creating firewall rule %s", err.Error(), ruleExpression)
				return err
			}
			worker.CFStateByAction[action].FilterIDByZoneID[zone.ID] = rule[0].Filter.ID
			zoneLogger.Infof("created firewall rule for %s action", action)
		}
	}
	worker.Logger.Info("setup of firewall rules complete")
	return nil
}

func (worker *CloudflareWorker) UpdateIPLists() error {
	// IP decisions are applied at account level
	newDecisonsByAction := dedupAndClassifyDecisionsByAction(worker.NewIPDecisions)
	expiredDecisonsByAction := dedupAndClassifyDecisionsByAction(worker.ExpiredIPDecisions)
	newIPSetByAction := make(map[string]map[string]IPSetItem)

	for action, decisions := range newDecisonsByAction {
		// In case some zones support this action and others don't,  we put this in account's default action.
		if !allZonesHaveAction(worker.Account.ZoneConfigs, action) {
			if worker.Account.DefaultAction == "none" {
				worker.Logger.Debugf("dropping IP decisions with unsupported action %s", action)
				continue
			}
			action = worker.Account.DefaultAction
			worker.Logger.Debugf("ip action defaulted to %s", action)
		}
		for ip, item := range worker.CFStateByAction[action].IPListState.IPSet {
			if _, ok := newIPSetByAction[action]; !ok {
				newIPSetByAction[action] = make(map[string]IPSetItem)
			}
			newIPSetByAction[action][ip] = item
		}

		for _, decision := range decisions {
			if _, ok := newIPSetByAction[action]; !ok {
				newIPSetByAction[action] = make(map[string]IPSetItem)
			}
			if _, ok := newIPSetByAction[action][*decision.Value]; !ok {
				newIPSetByAction[action][*decision.Value] = IPSetItem{
					CreatedAt: time.Now(),
				}
			}
		}
	}

	for action, decisions := range expiredDecisonsByAction {
		// In case some zones support this action and others don't,  we put this in account's default action.
		if !allZonesHaveAction(worker.Account.ZoneConfigs, action) {
			if worker.Account.DefaultAction == "none" {
				worker.Logger.Debugf("dropping IP decisions with unsupported action %s", action)
				continue
			}
			action = worker.Account.DefaultAction
			worker.Logger.Debugf("ip action defaulted to %s", action)
		}
		if _, ok := newIPSetByAction[action]; !ok {
			newIPSetByAction[action] = make(map[string]IPSetItem)
			for ip, item := range worker.CFStateByAction[action].IPListState.IPSet {
				newIPSetByAction[action][ip] = item
			}
		}
		for _, decision := range decisions {
			if _, ok := worker.CFStateByAction[action].IPListState.IPSet[*decision.Value]; ok {
				delete(newIPSetByAction[action], *decision.Value)
			}
		}
	}

	for action := range worker.CFStateByAction {
		var dropCount int
		newIPSetByAction[action], dropCount = keepLatestNIPSetItems(newIPSetByAction[action], *worker.Account.TotalIPListCapacity)
		if dropCount > 0 {
			worker.Logger.Warnf("%d IPs won't be inserted/kept to avoid exceeding IP list limit", dropCount)
		}
	}

	for action, set := range newIPSetByAction {
		if reflect.DeepEqual(worker.CFStateByAction[action].IPListState.IPSet, set) {
			log.Info("no changes to IP rules ")
			continue
		}
		if len(set) == 0 {
			// The ReplaceIPListItemsAsync method doesn't allow to empty the list.
			// Hence we only add one mock IP and later delete it. To do this we add the mock IP
			// in the set and continue as usual, and end up with 1 item in the IP list. Then the``
			// defer call takes care of cleaning up the extra IP.
			worker.Logger.Warningf("emptying IP list for %s action", action)
			set["10.0.0.1"] = IPSetItem{
				CreatedAt: time.Now(),
			}
			defer func(action string) {
				ipListId := worker.CFStateByAction[action].IPListState.IPList.ID
				items, err := worker.getAPI().ListIPListItems(worker.Ctx, ipListId)
				if err != nil {
					worker.Logger.Error(err)
					return
				}
				_, err = worker.getAPI().DeleteIPListItems(worker.Ctx, ipListId, cloudflare.IPListItemDeleteRequest{
					Items: []cloudflare.IPListItemDeleteItemRequest{
						{
							ID: items[0].ID,
						},
					},
				})
				if err != nil {
					worker.Logger.Error(err)
				}
				worker.CFStateByAction[action].IPListState.IPSet = make(map[string]IPSetItem)
				worker.CFStateByAction[action].IPListState.IPList.NumItems = 0
				worker.Logger.Infof("emptied IP list for %s action", action)

			}(action)
		}
		req := make([]cloudflare.IPListItemCreateRequest, 0)
		for ip := range set {
			req = append(req, cloudflare.IPListItemCreateRequest{
				IP: ip,
			})
		}
		ret, err := worker.getAPI().ReplaceIPListItemsAsync(worker.Ctx, worker.CFStateByAction[action].IPListState.IPList.ID, req)
		if err != nil {
			return err
		}
	POLL_LOOP:
		for {
			res, err := worker.getAPI().GetIPListBulkOperation(worker.Ctx, ret.Result.OperationID)
			if err != nil {
				return err
			}
			switch res.Status {
			case "failed":
				return fmt.Errorf("failed during polling got error %s ", res.Error)
			case "pending", "running":
			case "completed":
				break POLL_LOOP
			default:
				return fmt.Errorf("unexpected status %s while polling ", res.Status)
			}
			time.Sleep(time.Second)
		}
		newItemCount, deletedItemCount := calculateIPSetDiff(set, worker.CFStateByAction[action].IPListState.IPSet)
		log.Infof("added %d new IPs and deleted %d IPs", newItemCount, deletedItemCount)
		worker.CFStateByAction[action].IPListState.IPSet = set
		worker.CFStateByAction[action].IPListState.IPList.NumItems = len(set)
	}

	worker.ExpiredIPDecisions = make([]*models.Decision, 0)
	worker.NewIPDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) SetUpCloudflareResources() error {
	if err := worker.importExistingInfra(); err != nil {
		return err
	}

	err := worker.createMissingIPLists()
	if err != nil {
		worker.Logger.Errorf("error %s in creating IP List", err.Error())
		return err
	}
	worker.Logger.Debug("ip list setup complete")
	err = worker.createMissingRules()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}
	return nil
}

type InterceptLogger struct {
	Tripper http.RoundTripper
	logger  *log.Logger
}

func (lrt InterceptLogger) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		var buf bytes.Buffer
		tmp := io.TeeReader(req.Body, &buf)
		body, err := ioutil.ReadAll(tmp)
		if err != nil {
			return nil, err
		}
		lrt.logger.Debugf("%s  %s", req.URL, string(body))
		req.Body = io.NopCloser(&buf)
	} else {
		lrt.logger.Debugf("%s ", req.URL)
	}
	beginTime := time.Now()
	res, e := lrt.Tripper.RoundTrip(req)
	finishTime := time.Now()
	ResponseTime.Observe(float64(finishTime.Sub(beginTime).Milliseconds()))
	return res, e
}

func NewCloudflareClient(token string, accountID string, logger *log.Logger) (*cloudflare.API, error) {
	httpClient := &http.Client{
		Transport: InterceptLogger{
			Tripper: http.DefaultTransport,
			logger:  logger,
		},
	}
	z, err := cloudflare.NewWithAPIToken(token, cloudflare.UsingAccount(accountID), cloudflare.HTTPClient(httpClient))
	return z, err
}

func (worker *CloudflareWorker) Init() error {
	var err error
	worker.Logger = log.WithFields(log.Fields{"account_id": worker.Account.ID})
	if worker.API == nil { // this for easy swapping during tests
		worker.API, err = NewCloudflareClient(worker.Account.Token, worker.Account.ID, worker.APILogger)
		if err != nil {
			worker.Logger.Error(err.Error())
			return err
		}
	}
	worker.NewIPDecisions = make([]*models.Decision, 0)
	worker.ExpiredIPDecisions = make([]*models.Decision, 0)
	worker.CFStateByAction = make(map[string]*CloudflareState)
	worker.FirewallRulesByZoneID = make(map[string]*[]cloudflare.FirewallRule)
	zones, err := worker.cachedListZones()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}
	zoneByID := make(map[string]cloudflare.Zone)
	for _, zone := range zones {
		zoneByID[zone.ID] = zone
	}

	for _, z := range worker.Account.ZoneConfigs {
		zone, ok := zoneByID[z.ID]
		if !ok {
			return fmt.Errorf("account %s doesn't have access to zone %s", worker.Account.ID, z.ID)
		}

		if !zone.Plan.IsSubscribed && len(z.Actions) > 1 {
			// FIXME this is probably wrong.
			return fmt.Errorf("zone %s 's plan doesn't support multiple actionss", z.ID)
		}

		for _, action := range z.Actions {
			worker.CFStateByAction[action] = &CloudflareState{
				AccountID: worker.Account.ID,
				Action:    action,
			}
			worker.CFStateByAction[action].FilterIDByZoneID = make(map[string]string)
			worker.CFStateByAction[action].CountrySet = make(map[string]struct{})
			worker.CFStateByAction[action].AutonomousSystemSet = make(map[string]struct{})
		}
	}
	return err
}

func (worker *CloudflareWorker) getContainerByDecisionScope(scope string, decisionIsExpired bool) (*([]*models.Decision), error) {
	var containerByDecisionScope map[string]*([]*models.Decision)
	if decisionIsExpired {
		containerByDecisionScope = map[string]*([]*models.Decision){
			"IP":      &worker.ExpiredIPDecisions,
			"RANGE":   &worker.ExpiredIPDecisions, // Cloudflare IP lists handle ranges fine
			"COUNTRY": &worker.ExpiredCountryDecisions,
			"AS":      &worker.ExpiredASDecisions,
		}
	} else {
		containerByDecisionScope = map[string]*([]*models.Decision){
			"IP":      &worker.NewIPDecisions,
			"RANGE":   &worker.NewIPDecisions, // Cloudflare IP lists handle ranges fine
			"COUNTRY": &worker.NewCountryDecisions,
			"AS":      &worker.NewASDecisions,
		}
	}
	scope = strings.ToUpper(scope)
	if container, ok := containerByDecisionScope[scope]; !ok {
		return nil, fmt.Errorf("%s scope is not supported", scope)
	} else {
		return container, nil
	}
}
func (worker *CloudflareWorker) insertDecision(decision *models.Decision, decisionIsExpired bool) {
	container, err := worker.getContainerByDecisionScope(*decision.Scope, decisionIsExpired)
	if err != nil {
		worker.Logger.Debugf("ignored new decision with scope=%s, type=%s, value=%s", *decision.Scope, *decision.Type, *decision.Value)
		return
	}
	decisionStatus := "new"
	if decisionIsExpired {
		decisionStatus = "expired"
	}
	worker.Logger.Debugf("found %s decision with value=%s, scope=%s, type=%s", decisionStatus, *decision.Value, *decision.Scope, *decision.Type)
	*container = append(*container, decision)
}

func (worker *CloudflareWorker) CollectLAPIStream(streamDecision *models.DecisionsStreamResponse) {
	for _, decision := range streamDecision.New {
		worker.insertDecision(decision, false)
	}
	for _, decision := range streamDecision.Deleted {
		worker.insertDecision(decision, true)
	}
}

func (worker *CloudflareWorker) SendASBans() error {
	decisionsByAction := dedupAndClassifyDecisionsByAction(worker.NewASDecisions)
	for _, zoneCfg := range worker.Account.ZoneConfigs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneCfg.ID})
		for action, decisions := range decisionsByAction {
			action = worker.normalizeActionForZone(action, zoneCfg)
			for _, decision := range decisions {
				if _, ok := worker.CFStateByAction[action].AutonomousSystemSet[*decision.Value]; !ok {
					zoneLogger.Debugf("found new AS ban for %s", *decision.Value)
					worker.CFStateByAction[action].AutonomousSystemSet[*decision.Value] = struct{}{}
				}
			}
		}
	}
	worker.NewASDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteASBans() error {
	decisionsByAction := dedupAndClassifyDecisionsByAction(worker.ExpiredASDecisions)
	for _, zoneCfg := range worker.Account.ZoneConfigs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneCfg.ID})
		for action, decisions := range decisionsByAction {
			action = worker.normalizeActionForZone(action, zoneCfg)
			for _, decision := range decisions {
				if _, ok := worker.CFStateByAction[action].AutonomousSystemSet[*decision.Value]; ok {
					zoneLogger.Debugf("found expired AS ban for %s", *decision.Value)
					delete(worker.CFStateByAction[action].AutonomousSystemSet, *decision.Value)
				}
			}
		}
	}
	worker.ExpiredASDecisions = make([]*models.Decision, 0)
	return nil
}

func keepLatestNIPSetItems(set map[string]IPSetItem, n int) (map[string]IPSetItem, int) {
	currentItems := len(set)
	if currentItems <= n {
		return set, 0
	}
	newSet := make(map[string]IPSetItem)
	itemsCreationTime := make([]time.Time, len(set))
	i := 0
	for _, val := range set {
		itemsCreationTime[i] = val.CreatedAt
		i++
	}
	// We use this to find the cutoff duration. This can be improved using more
	// sophisticated algo  at cost of more code.
	sort.Slice(itemsCreationTime, func(i, j int) bool {
		return itemsCreationTime[i].After(itemsCreationTime[j])
	})
	dropCount := 0
	tc := 0
	for ip, item := range set {
		if item.CreatedAt.After(itemsCreationTime[n-1]) || item.CreatedAt.Equal(itemsCreationTime[n-1]) {
			newSet[ip] = item
			tc++
		} else {
			dropCount++
		}
		if tc == n {
			break
		}
	}

	return newSet, dropCount
}

func (worker *CloudflareWorker) normalizeActionForZone(action string, zoneCfg ZoneConfig) string {
	zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneCfg.ID})
	if _, spAction := zoneCfg.ActionSet[action]; action == "defaulted" || !spAction {
		if action != "defaulted" {
			zoneLogger.Debugf("defaulting %s action to %s action", action, zoneCfg.Actions[0])
		}
		action = zoneCfg.Actions[0]
	}
	return action
}

func (worker *CloudflareWorker) SendCountryBans() error {
	decisionsByAction := dedupAndClassifyDecisionsByAction(worker.NewCountryDecisions)
	for _, zoneCfg := range worker.Account.ZoneConfigs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneCfg.ID})
		for action, decisions := range decisionsByAction {
			action = worker.normalizeActionForZone(action, zoneCfg)
			for _, decision := range decisions {
				if _, ok := worker.CFStateByAction[action].CountrySet[*decision.Value]; !ok {
					zoneLogger.Debugf("found new country ban for %s", *decision.Value)
					worker.CFStateByAction[action].CountrySet[*decision.Value] = struct{}{}
				}
			}
		}
	}
	worker.NewCountryDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) DeleteCountryBans() error {
	decisionsByAction := dedupAndClassifyDecisionsByAction(worker.ExpiredCountryDecisions)
	for _, zoneCfg := range worker.Account.ZoneConfigs {
		zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zoneCfg.ID})
		for action, decisions := range decisionsByAction {
			action = worker.normalizeActionForZone(action, zoneCfg)
			for _, decision := range decisions {
				if _, ok := worker.CFStateByAction[action].CountrySet[*decision.Value]; ok {
					zoneLogger.Debugf("found expired country ban for %s", *decision.Value)
					delete(worker.CFStateByAction[action].CountrySet, *decision.Value)
				}
			}
		}
	}
	worker.ExpiredCountryDecisions = make([]*models.Decision, 0)
	return nil
}

func (worker *CloudflareWorker) UpdateRules() error {
	for action, state := range worker.CFStateByAction {
		if !worker.CFStateByAction[action].UpdateExpr() {
			// expression is still same, why bother.
			worker.Logger.Debugf("rule for %s action is unchanged", action)
			continue
		}
		for _, zone := range worker.Account.ZoneConfigs {
			zoneLogger := worker.Logger.WithFields(log.Fields{"zone_id": zone.ID})
			updatedFilters := make([]cloudflare.Filter, 0)
			if _, ok := zone.ActionSet[action]; ok {
				// check whether this action is supported by this zone
				updatedFilters = append(updatedFilters, cloudflare.Filter{ID: state.FilterIDByZoneID[zone.ID], Expression: state.CurrExpr})
			}
			if len(updatedFilters) > 0 {
				zoneLogger.Infof("updating %d rules", len(updatedFilters))
				_, err := worker.getAPI().UpdateFilters(worker.Ctx, zone.ID, updatedFilters)
				if err != nil {
					return err
				}
			} else {
				zoneLogger.Debug("rules are same")
			}
		}
	}
	return nil
}

func (worker *CloudflareWorker) runProcessorOnDecisions(processor func() error, decisions []*models.Decision) {
	if len(decisions) == 0 {
		return
	}
	worker.Logger.Infof("processing decisions with scope=%s", *decisions[0].Scope)
	err := processor()
	if err != nil {
		worker.Logger.Error(err)
	}
	worker.Logger.Infof("done processing decisions with scope=%s", *decisions[0].Scope)

}

func (worker *CloudflareWorker) Run() error {
	err := worker.Init()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}

	err = worker.SetUpCloudflareResources()
	if err != nil {
		worker.Logger.Error(err.Error())
		return err
	}

	ticker := time.NewTicker(worker.UpdateFrequency)
	for {
		select {
		case <-ticker.C:
			worker.runProcessorOnDecisions(worker.UpdateIPLists, append(worker.NewIPDecisions, worker.ExpiredIPDecisions...))
			worker.runProcessorOnDecisions(worker.DeleteCountryBans, worker.ExpiredCountryDecisions)
			worker.runProcessorOnDecisions(worker.SendCountryBans, worker.NewCountryDecisions)
			worker.runProcessorOnDecisions(worker.DeleteASBans, worker.ExpiredASDecisions)
			worker.runProcessorOnDecisions(worker.SendASBans, worker.NewASDecisions)

			err = worker.UpdateRules()
			if err != nil {
				worker.Logger.Error(err)
				return err
			}

		case decisions := <-worker.LAPIStream:
			worker.Logger.Debug("collecting decisions from LAPI")
			worker.CollectLAPIStream(decisions)
		}
	}

}
