package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
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
			case syscall.SIGTERM:
				exitChan <- 0
			}
		}
	}()
	code := <-exitChan
	log.Infof("Shutting down cloudfare-bouncer service")
	os.Exit(code)
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

	var cfAPI cloudflareAPI
	cfAPI, err = cloudflare.NewWithAPIToken(conf.CloudflareAPIToken, cloudflare.UsingAccount(conf.CloudflareAccountID))

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

	cloudflareTicker := time.NewTicker(conf.CloudflareUpdateFrequency)

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
				addIPs := mapToSliceCreateRequest(addIPMap)
				deleteIPs := mapToSliceDeleteRequest(deleteIPMap)
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
				CollectLAPIStream(streamDecision, deleteIPMap, addIPMap, cloudflareIDByIP)
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
