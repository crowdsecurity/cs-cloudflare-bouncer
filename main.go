package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudflare/cloudflare-go"
	"github.com/coreos/go-systemd/daemon"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var t tomb.Tomb

func termHandler(sig os.Signal, ctx context.Context) error {
	// if err := ctx.ShutDown(); err != nil {
	// 	return err
	// }
	log.Infof("Shutting down\n")
	return nil
}

func HandleSignals(ctx context.Context) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM)

	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				if err := termHandler(s, ctx); err != nil {
					log.Fatalf("shutdown fail: %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Infof("Shutting down firewall-bouncer service")
	os.Exit(code)
}

func clearExistingCrowdSecIPList(ctx context.Context, cfAPI *cloudflare.API, conf *blockerConfig) error {
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

func removeIPListDependencies(ctx context.Context, cfAPI *cloudflare.API, conf *blockerConfig) error {
	rules, err := cfAPI.FirewallRules(ctx, conf.CloudflareZoneID, cloudflare.PaginationOptions{})
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if rule.Filter.Expression == "ip.src in $crowdsec" {
			err := cfAPI.DeleteFirewallRule(ctx, conf.CloudflareZoneID, rule.ID)
			if err != nil {
				return err
			}

			err = cfAPI.DeleteFilter(ctx, conf.CloudflareZoneID, rule.Filter.ID)
			if err != nil {
				return err
			}
			break
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

func setUpIPListAndFirewall(ctx context.Context, cfAPI *cloudflare.API, conf *blockerConfig) (string, error) {
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
		TickerInterval: conf.UpdateFrequencyYAML,
	}

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go csLapi.Run()
	cloudflareIDByIP := make(map[string]string)

	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Fatal("terminating bouncer process")
				return nil
			case streamDecision := <-csLapi.Stream:
				deleteIPMap := make(map[cloudflare.IPListItemDeleteItemRequest]bool)
				addIPMap := make(map[cloudflare.IPListItemCreateRequest]bool)

				for _, decision := range streamDecision.Deleted {
					if cloudflareIDByIP[*decision.Value] != "" {
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

				addIPs := make([]cloudflare.IPListItemCreateRequest, 0)
				for k := range addIPMap {
					addIPs = append(addIPs, k)
				}

				if len(addIPs) > 0 {
					ipItems, err := cfAPI.CreateIPListItems(ctx, ipListID, addIPs)
					if err != nil {
						log.Fatal(err)
					}

					for _, ipItem := range ipItems {
						cloudflareIDByIP[ipItem.IP] = ipItem.ID
					}
				}

				deleteIPs := make([]cloudflare.IPListItemDeleteItemRequest, 0)
				for k := range deleteIPMap {
					deleteIPs = append(deleteIPs, k)
				}

				if len(deleteIPs) > 0 {
					_, err := cfAPI.DeleteIPListItems(ctx, ipListID, cloudflare.IPListItemDeleteRequest{Items: deleteIPs})
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}
	})
	if conf.Daemon{
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
