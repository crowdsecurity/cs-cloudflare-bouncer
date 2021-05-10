package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/coreos/go-systemd/daemon"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var t tomb.Tomb

func HandleSignals(ctx context.Context) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				exitChan <- 0
			}
		}
	}()
	code := <-exitChan
	log.Infof("Shutting down firewall-bouncer service")
	os.Exit(code)
}

func clearExistingCrowdSecIPList(ctx context.Context, cfAPI *cloudflare.API, conf *bouncerConfig) error {
	ipLists, err := cfAPI.ListIPLists(ctx)
	if err != nil {
		return err
	}

	id, err := getIPListID(ipLists)
	if err != nil {
		return err
	}

	removeIPListDependencies(ctx, cfAPI, conf)

	_, err = cfAPI.DeleteIPList(ctx, id)
	if err != nil {
		return err
	}
	return nil
}

func removeIPListDependencies(ctx context.Context, cfAPI *cloudflare.API, conf *bouncerConfig) error {
	rules, err := cfAPI.FirewallRules(ctx, conf.CloudflareZoneID, cloudflare.PaginationOptions{})
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if strings.Contains(rule.Filter.Expression, "$"+conf.CloudflareIPListName) {
			err := cfAPI.DeleteFirewallRule(ctx, conf.CloudflareZoneID, rule.ID)
			if err != nil {
				return err
			}

			err = cfAPI.DeleteFilter(ctx, conf.CloudflareZoneID, rule.Filter.ID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getIPListID(ipLists []cloudflare.IPList) (string, error) {
	for _, ipList := range ipLists {
		if ipList.Name == "crowdsec" {
			return ipList.ID, nil
		}
	}
	return "", errors.New("crowdsec ip list not found")
}

func setUpIPListAndFirewall(ctx context.Context, cfAPI *cloudflare.API, conf *bouncerConfig) (string, error) {
	clearExistingCrowdSecIPList(ctx, cfAPI, conf)
	ipList, err := cfAPI.CreateIPList(ctx, "crowdsec", "IP list managed by crowdsec bouncer", "ip")
	if err != nil {
		return "", err
	}

	firewallRules := []cloudflare.FirewallRule{{Filter: cloudflare.Filter{Expression: "ip.src in $crowdsec"}, Action: conf.Action}}
	_, err = cfAPI.CreateFirewallRules(ctx, conf.CloudflareZoneID, firewallRules)
	if err != nil {
		return "", err
	}
	return ipList.ID, nil
}

func main() {

	configPath := flag.String("c", "", "path to config file")
	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}

	ctx := context.Background()
	conf, err := NewConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	cfAPI, err := cloudflare.NewWithAPIToken(
		conf.CloudflareAPIToken, cloudflare.UsingAccount(conf.CloudflareAccountID))

	if err != nil {
		log.Fatal(err)
	}

	ipListID, err := setUpIPListAndFirewall(ctx, cfAPI, conf)
	if err != nil {
		log.Fatal(err)
	}

	csLapi := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
	}

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	duration, _ := time.ParseDuration(conf.CloudflareUpdateFrequencyYAML)
	cloudflareTicker := time.NewTicker(duration)

	go csLapi.Run()

	cloudflareIDByIP := make(map[string]string)
	// These maps are used to create slices without dup IPS
	deleteIPMap := make(map[cloudflare.IPListItemDeleteItemRequest]bool)
	addIPMap := make(map[cloudflare.IPListItemCreateRequest]bool)

	t.Go(func() error {
		for {
			select {
			case <-t.Dying():
				return errors.New("tomb dying")

			case <-cloudflareTicker.C:
				addIPs := make([]cloudflare.IPListItemCreateRequest, 0)
				deleteIPs := make([]cloudflare.IPListItemDeleteItemRequest, 0)
				for k := range addIPMap {
					addIPs = append(addIPs, k)
				}

				if len(addIPs) > 0 {
					ipItems, err := cfAPI.CreateIPListItems(ctx, ipListID, addIPs)
					log.Infof("making API call to cloudflare for adding '%d' decisions", len(addIPs))

					if err != nil {
						log.Fatal(err)
					}

					for _, ipItem := range ipItems {
						cloudflareIDByIP[ipItem.IP] = ipItem.ID
					}
				}

				for k := range deleteIPMap {
					deleteIPs = append(deleteIPs, k)
				}

				if len(deleteIPs) > 0 {
					_, err := cfAPI.DeleteIPListItems(ctx, ipListID, cloudflare.IPListItemDeleteRequest{Items: deleteIPs})
					log.Infof("making API call to cloudflare to delete '%d' decisions", len(deleteIPs))
					if err != nil {
						log.Fatal(err)
					}
				}

				// Flush
				deleteIPMap = make(map[cloudflare.IPListItemDeleteItemRequest]bool)
				addIPMap = make(map[cloudflare.IPListItemCreateRequest]bool)

			case streamDecision := <-csLapi.Stream:
				log.Printf("processing new and deleted decisions from crowdsec LAPI")
				for _, decision := range streamDecision.Deleted {
					if _, ok := cloudflareIDByIP[*decision.Value]; ok {
						deleteIPMap[cloudflare.IPListItemDeleteItemRequest{ID: cloudflareIDByIP[*decision.Value]}] = true
						delete(cloudflareIDByIP, *decision.Value)
					}
				}

				for _, decision := range streamDecision.New {
					addIPMap[cloudflare.IPListItemCreateRequest{
						IP:      *decision.Value,
						Comment: "Added by crowdsec bouncer",
					}] = true
				}

			}
		}
	})
	if conf.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Fatalf("Failed to notify: %v", err)
		}
		HandleSignals(ctx)
	}

	err = t.Wait()
	if err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
